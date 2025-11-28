import express from 'express';
import { MongoClient, ServerApiVersion, ObjectId } from 'mongodb';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import path from 'path';
import { fileURLToPath } from 'url';
import nodemailer from 'nodemailer';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Configuration
const CONFIG = {
    MONGODB_URI: process.env.MONGODB_URI || "mongodb+srv://schoolchat_user:tukubhuyan123@cluster0.i386mxq.mongodb.net/?retryWrites=true&w=majority",
    JWT_SECRET: process.env.JWT_SECRET || "ZetterSecureJWTKey_2024@SuperSafe!Token_ForTwitterClone#Encryption$MegaStrong",
    PORT: process.env.PORT || 3000,
    SMTP_HOST: process.env.SMTP_HOST || "smtp.gmail.com",
    SMTP_PORT: process.env.SMTP_PORT || 587,
    SMTP_USER: process.env.SMTP_USER || "",
    SMTP_PASS: process.env.SMTP_PASS || ""
};

// Initialize Express
const app = express();

// Trust proxy
app.set('trust proxy', 1);

// Middleware
app.use(helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
    contentSecurityPolicy: false
}));
app.use(compression());
app.use(cors({
    origin: ['http://localhost:3000', 'https://zetter-x.onrender.com'],
    credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, '.'))); // Serve from current directory

// Rate Limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: 'Too many requests from this IP'
});
app.use(limiter);

// Database Connection
let db, client;

async function connectDB() {
    try {
        console.log('Connecting to MongoDB...');
        client = new MongoClient(CONFIG.MONGODB_URI, {
            serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
            maxPoolSize: 50
        });
        await client.connect();
        db = client.db('twitter_clone');
        
        // Create indexes
        await db.collection('users').createIndex({ username: 1 }, { unique: true });
        await db.collection('users').createIndex({ email: 1 }, { unique: true });
        await db.collection('tweets').createIndex({ createdAt: -1 });
        await db.collection('tweets').createIndex({ userId: 1 });
        await db.collection('tweets').createIndex({ hashtags: 1 });
        await db.collection('follows').createIndex({ followerId: 1, followingId: 1 }, { unique: true });
        await db.collection('otps').createIndex({ expires: 1 }, { expireAfterSeconds: 600 });
        
        console.log('MongoDB Connected');
        await createAdminUser();
        
    } catch (error) {
        console.error('MongoDB connection failed:', error);
        process.exit(1);
    }
}

async function createAdminUser() {
    try {
        const adminExists = await db.collection('users').findOne({ username: 'admin' });
        if (!adminExists) {
            const hashedPassword = await bcrypt.hash('admin123', 12);
            await db.collection('users').insertOne({
                username: 'admin',
                email: 'sourovb768@gmail.com',
                password: hashedPassword,
                displayName: 'Administrator',
                bio: 'System Administrator',
                avatar: 'A',
                isVerified: true,
                followersCount: 0,
                followingCount: 0,
                tweetsCount: 0,
                joinedDate: new Date(),
                role: 'admin'
            });
            console.log('Admin user created');
        }
    } catch (error) {
        console.log('Admin user already exists');
    }
}

// Utility Functions
function generateToken(user) {
    return jwt.sign(
        { userId: user._id.toString(), username: user.username, role: user.role },
        CONFIG.JWT_SECRET,
        { expiresIn: '7d' }
    );
}

async function verifyToken(token) {
    try {
        return jwt.verify(token, CONFIG.JWT_SECRET);
    } catch (error) {
        return null;
    }
}

// Authentication Middleware
async function authenticate(req, res, next) {
    try {
        const token = req.headers.authorization?.replace('Bearer ', '');
        if (!token) {
            return res.status(401).json({ success: false, error: 'Authentication required' });
        }

        const decoded = await verifyToken(token);
        if (!decoded) {
            return res.status(401).json({ success: false, error: 'Invalid token' });
        }

        const user = await db.collection('users').findOne({ _id: new ObjectId(decoded.userId) });
        if (!user) {
            return res.status(401).json({ success: false, error: 'User not found' });
        }

        req.user = user;
        next();
    } catch (error) {
        res.status(401).json({ success: false, error: 'Authentication failed' });
    }
}

// OTP Email Service
async function sendOTP(email, otpCode) {
    try {
        if (!CONFIG.SMTP_USER || !CONFIG.SMTP_PASS) {
            console.log('OTP would be sent to:', email, 'Code:', otpCode);
            return true;
        }

        const transporter = nodemailer.createTransport({
            host: CONFIG.SMTP_HOST,
            port: CONFIG.SMTP_PORT,
            auth: {
                user: CONFIG.SMTP_USER,
                pass: CONFIG.SMTP_PASS
            }
        });

        await transporter.sendMail({
            from: CONFIG.SMTP_USER,
            to: email,
            subject: 'Zetter - Verify Your Email',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #1DA1F2;">Zetter</h2>
                    <p>Your verification code is:</p>
                    <h1 style="font-size: 32px; color: #1DA1F2; letter-spacing: 5px;">${otpCode}</h1>
                    <p>This code will expire in 10 minutes.</p>
                    <p>If you didn't request this, please ignore this email.</p>
                </div>
            `
        });

        return true;
    } catch (error) {
        console.error('Email error:', error);
        return false;
    }
}

// ===== API ROUTES =====

// Health Check
app.get('/api/health', async (req, res) => {
    try {
        await db.collection('users').findOne({});
        res.json({
            status: 'Healthy',
            version: '2.0.0',
            database: 'MongoDB',
            uptime: process.uptime()
        });
    } catch (error) {
        res.status(500).json({ status: 'Unhealthy', error: error.message });
    }
});

// Authentication Routes
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { username, email, password, displayName } = req.body;

        if (!username || !email || !password || !displayName) {
            return res.json({ success: false, error: 'All fields are required' });
        }

        const cleanUsername = username.toLowerCase().trim();
        const cleanEmail = email.toLowerCase().trim();
        const cleanDisplayName = displayName.trim();

        const existingUser = await db.collection('users').findOne({
            $or: [
                { username: cleanUsername },
                { email: cleanEmail }
            ]
        });

        if (existingUser) {
            if (existingUser.username === cleanUsername) {
                return res.json({ success: false, error: 'Username already exists' });
            }
            if (existingUser.email === cleanEmail) {
                return res.json({ success: false, error: 'Email already exists' });
            }
        }

        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpiry = new Date(Date.now() + 10 * 60 * 1000);
        const hashedPassword = await bcrypt.hash(password, 12);

        const user = {
            username: cleanUsername,
            email: cleanEmail,
            password: hashedPassword,
            displayName: cleanDisplayName,
            bio: '',
            avatar: cleanDisplayName.charAt(0).toUpperCase(),
            isVerified: false,
            followersCount: 0,
            followingCount: 0,
            tweetsCount: 0,
            joinedDate: new Date(),
            role: 'user'
        };

        const result = await db.collection('users').insertOne(user);
        const newUser = await db.collection('users').findOne({ _id: result.insertedId });

        await db.collection('otps').insertOne({
            userId: result.insertedId,
            email: cleanEmail,
            code: otpCode,
            expires: otpExpiry,
            attempts: 0
        });

        await sendOTP(email, otpCode);
        const tempToken = generateToken(newUser);

        res.json({
            success: true,
            message: 'Registration successful! Please check your email for verification code.',
            tempToken,
            user: {
                id: newUser._id,
                username: newUser.username,
                displayName: newUser.displayName,
                avatar: newUser.avatar,
                isVerified: false
            }
        });

    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ success: false, error: 'Registration failed' });
    }
});

app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const { email, otpCode } = req.body;

        if (!email || !otpCode) {
            return res.json({ success: false, error: 'Email and OTP code are required' });
        }

        const otpRecord = await db.collection('otps').findOne({
            email: email.toLowerCase(),
            expires: { $gt: new Date() }
        });

        if (!otpRecord) {
            return res.json({ success: false, error: 'OTP expired or invalid' });
        }

        if (otpRecord.attempts >= 3) {
            return res.json({ success: false, error: 'Too many attempts. Please request a new OTP.' });
        }

        if (otpRecord.code !== otpCode) {
            await db.collection('otps').updateOne(
                { _id: otpRecord._id },
                { $inc: { attempts: 1 } }
            );
            return res.json({ success: false, error: 'Invalid OTP code' });
        }

        await db.collection('users').updateOne(
            { _id: otpRecord.userId },
            { $set: { isVerified: true } }
        );

        await db.collection('otps').deleteOne({ _id: otpRecord._id });

        const user = await db.collection('users').findOne({ _id: otpRecord.userId });
        const token = generateToken(user);

        res.json({
            success: true,
            message: 'Email verified successfully!',
            token,
            user: {
                id: user._id,
                username: user.username,
                displayName: user.displayName,
                avatar: user.avatar,
                isVerified: true,
                followersCount: user.followersCount,
                followingCount: user.followingCount
            }
        });

    } catch (error) {
        console.error('OTP verification error:', error);
        res.status(500).json({ success: false, error: 'Verification failed' });
    }
});

app.post('/api/auth/resend-otp', async (req, res) => {
    try {
        const { email } = req.body;

        const user = await db.collection('users').findOne({ email: email.toLowerCase() });
        if (!user) {
            return res.json({ success: false, error: 'User not found' });
        }

        if (user.isVerified) {
            return res.json({ success: false, error: 'Email already verified' });
        }

        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpiry = new Date(Date.now() + 10 * 60 * 1000);

        await db.collection('otps').deleteMany({ email: email.toLowerCase() });
        await db.collection('otps').insertOne({
            userId: user._id,
            email: email.toLowerCase(),
            code: otpCode,
            expires: otpExpiry,
            attempts: 0
        });

        await sendOTP(email, otpCode);

        res.json({
            success: true,
            message: 'New verification code sent to your email!'
        });

    } catch (error) {
        console.error('Resend OTP error:', error);
        res.status(500).json({ success: false, error: 'Failed to resend OTP' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.json({ success: false, error: 'Username and password are required' });
        }

        const user = await db.collection('users').findOne({
            username: username.toLowerCase()
        });

        if (!user) {
            return res.json({ success: false, error: 'Invalid username or password' });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.json({ success: false, error: 'Invalid username or password' });
        }

        if (!user.isVerified) {
            return res.json({ success: false, error: 'Please verify your email first', needsVerification: true });
        }

        const token = generateToken(user);

        res.json({
            success: true,
            message: 'Login successful!',
            token,
            user: {
                id: user._id,
                username: user.username,
                displayName: user.displayName,
                avatar: user.avatar,
                isVerified: user.isVerified,
                followersCount: user.followersCount,
                followingCount: user.followingCount,
                bio: user.bio
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, error: 'Login failed' });
    }
});

app.get('/api/auth/me', authenticate, async (req, res) => {
    try {
        res.json({
            success: true,
            user: {
                id: req.user._id,
                username: req.user.username,
                displayName: req.user.displayName,
                avatar: req.user.avatar,
                bio: req.user.bio,
                isVerified: req.user.isVerified,
                followersCount: req.user.followersCount,
                followingCount: req.user.followingCount,
                tweetsCount: req.user.tweetsCount,
                joinedDate: req.user.joinedDate
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Failed to get user data' });
    }
});

// Tweet Routes
app.post('/api/tweets', authenticate, async (req, res) => {
    try {
        const { content, replyTo } = req.body;

        if (!content || content.trim().length === 0) {
            return res.json({ success: false, error: 'Tweet content cannot be empty' });
        }

        if (content.length > 280) {
            return res.json({ success: false, error: 'Tweet cannot exceed 280 characters' });
        }

        const tweet = {
            userId: req.user._id,
            username: req.user.username,
            displayName: req.user.displayName,
            avatar: req.user.avatar,
            content: content.trim(),
            hashtags: extractHashtags(content),
            mentions: extractMentions(content),
            likes: [],
            retweets: [],
            replies: [],
            likesCount: 0,
            retweetsCount: 0,
            repliesCount: 0,
            viewCount: 0,
            createdAt: new Date(),
            replyTo: replyTo || null
        };

        const result = await db.collection('tweets').insertOne(tweet);
        const newTweet = await db.collection('tweets').findOne({ _id: result.insertedId });

        await db.collection('users').updateOne(
            { _id: req.user._id },
            { $inc: { tweetsCount: 1 } }
        );

        for (const mention of tweet.mentions) {
            const mentionedUser = await db.collection('users').findOne({ username: mention.slice(1) });
            if (mentionedUser && mentionedUser._id.toString() !== req.user._id.toString()) {
                await createNotification(mentionedUser._id, 'mention', req.user._id, result.insertedId);
            }
        }

        res.json({
            success: true,
            tweet: newTweet
        });

    } catch (error) {
        console.error('Create tweet error:', error);
        res.status(500).json({ success: false, error: 'Failed to create tweet' });
    }
});

app.get('/api/tweets/timeline', authenticate, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;

        const following = await db.collection('follows').find({
            followerId: req.user._id
        }).toArray();

        const followingIds = following.map(f => f.followingId);
        followingIds.push(req.user._id);

        const tweets = await db.collection('tweets').find({
            userId: { $in: followingIds },
            replyTo: null
        })
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .toArray();

        res.json({
            success: true,
            tweets,
            pagination: {
                page,
                limit,
                hasMore: tweets.length === limit
            }
        });

    } catch (error) {
        console.error('Timeline error:', error);
        res.status(500).json({ success: false, error: 'Failed to load timeline' });
    }
});

app.get('/api/tweets/:id', authenticate, async (req, res) => {
    try {
        const tweet = await db.collection('tweets').findOne({
            _id: new ObjectId(req.params.id)
        });

        if (!tweet) {
            return res.json({ success: false, error: 'Tweet not found' });
        }

        await db.collection('tweets').updateOne(
            { _id: tweet._id },
            { $inc: { viewCount: 1 } }
        );

        const replies = await db.collection('tweets').find({
            replyTo: req.params.id
        })
        .sort({ createdAt: 1 })
        .toArray();

        res.json({
            success: true,
            tweet: {
                ...tweet,
                replies
            }
        });

    } catch (error) {
        console.error('Get tweet error:', error);
        res.status(500).json({ success: false, error: 'Failed to get tweet' });
    }
});

app.post('/api/tweets/:id/like', authenticate, async (req, res) => {
    try {
        const tweet = await db.collection('tweets').findOne({
            _id: new ObjectId(req.params.id)
        });

        if (!tweet) {
            return res.json({ success: false, error: 'Tweet not found' });
        }

        const hasLiked = tweet.likes.includes(req.user._id.toString());

        if (hasLiked) {
            await db.collection('tweets').updateOne(
                { _id: tweet._id },
                { 
                    $pull: { likes: req.user._id.toString() },
                    $inc: { likesCount: -1 }
                }
            );
        } else {
            await db.collection('tweets').updateOne(
                { _id: tweet._id },
                { 
                    $addToSet: { likes: req.user._id.toString() },
                    $inc: { likesCount: 1 }
                }
            );

            if (tweet.userId.toString() !== req.user._id.toString()) {
                await createNotification(tweet.userId, 'like', req.user._id, tweet._id);
            }
        }

        res.json({
            success: true,
            liked: !hasLiked
        });

    } catch (error) {
        console.error('Like tweet error:', error);
        res.status(500).json({ success: false, error: 'Failed to like tweet' });
    }
});

// User Routes
app.post('/api/users/:username/follow', authenticate, async (req, res) => {
    try {
        const targetUser = await db.collection('users').findOne({
            username: req.params.username.toLowerCase()
        });

        if (!targetUser) {
            return res.json({ success: false, error: 'User not found' });
        }

        if (targetUser._id.toString() === req.user._id.toString()) {
            return res.json({ success: false, error: 'Cannot follow yourself' });
        }

        const isFollowing = await db.collection('follows').findOne({
            followerId: req.user._id,
            followingId: targetUser._id
        });

        if (isFollowing) {
            await db.collection('follows').deleteOne({
                followerId: req.user._id,
                followingId: targetUser._id
            });

            await db.collection('users').updateOne(
                { _id: req.user._id },
                { $inc: { followingCount: -1 } }
            );
            await db.collection('users').updateOne(
                { _id: targetUser._id },
                { $inc: { followersCount: -1 } }
            );

        } else {
            await db.collection('follows').insertOne({
                followerId: req.user._id,
                followingId: targetUser._id,
                createdAt: new Date()
            });

            await db.collection('users').updateOne(
                { _id: req.user._id },
                { $inc: { followingCount: 1 } }
            );
            await db.collection('users').updateOne(
                { _id: targetUser._id },
                { $inc: { followersCount: 1 } }
            );

            await createNotification(targetUser._id, 'follow', req.user._id);
        }

        res.json({
            success: true,
            following: !isFollowing
        });

    } catch (error) {
        console.error('Follow error:', error);
        res.status(500).json({ success: false, error: 'Failed to follow user' });
    }
});

app.get('/api/users/:username', authenticate, async (req, res) => {
    try {
        const user = await db.collection('users').findOne({
            username: req.params.username.toLowerCase()
        });

        if (!user) {
            return res.json({ success: false, error: 'User not found' });
        }

        const isFollowing = await db.collection('follows').findOne({
            followerId: req.user._id,
            followingId: user._id
        });

        const tweets = await db.collection('tweets').find({
            userId: user._id,
            replyTo: null
        })
        .sort({ createdAt: -1 })
        .limit(20)
        .toArray();

        res.json({
            success: true,
            user: {
                id: user._id,
                username: user.username,
                displayName: user.displayName,
                avatar: user.avatar,
                bio: user.bio,
                followersCount: user.followersCount,
                followingCount: user.followingCount,
                tweetsCount: user.tweetsCount,
                joinedDate: user.joinedDate,
                isVerified: user.isVerified
            },
            isFollowing: !!isFollowing,
            tweets
        });

    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({ success: false, error: 'Failed to get user profile' });
    }
});

app.get('/api/users/suggestions', authenticate, async (req, res) => {
    try {
        const following = await db.collection('follows').find({
            followerId: req.user._id
        }).toArray();

        const followingIds = following.map(f => f.followingId);
        followingIds.push(req.user._id);

        const suggestions = await db.collection('users').aggregate([
            { $match: { _id: { $nin: followingIds } } },
            { $sample: { size: 3 } },
            { $project: {
                displayName: 1,
                username: 1,
                avatar: 1,
                followersCount: 1,
                bio: 1
            }}
        ]).toArray();

        res.json({
            success: true,
            users: suggestions
        });

    } catch (error) {
        console.error('Suggestions error:', error);
        res.json({
            success: true,
            users: [
                { 
                    _id: '1', 
                    displayName: 'Tech News', 
                    username: 'technews', 
                    avatar: 'T', 
                    followersCount: 1200000,
                    bio: 'Latest technology news and updates'
                },
                { 
                    _id: '2', 
                    displayName: 'Sports Center', 
                    username: 'sports', 
                    avatar: 'S', 
                    followersCount: 890000,
                    bio: 'Sports news and highlights'
                },
                { 
                    _id: '3', 
                    displayName: 'Music World', 
                    username: 'music', 
                    avatar: 'M', 
                    followersCount: 2100000,
                    bio: 'Your daily music updates'
                }
            ]
        });
    }
});

app.put('/api/users/profile', authenticate, async (req, res) => {
    try {
        const { displayName, bio, avatar } = req.body;

        const updateData = {};
        if (displayName) updateData.displayName = displayName;
        if (bio !== undefined) updateData.bio = bio;
        if (avatar) updateData.avatar = avatar;

        await db.collection('users').updateOne(
            { _id: req.user._id },
            { $set: updateData }
        );

        const updatedUser = await db.collection('users').findOne({ _id: req.user._id });

        res.json({
            success: true,
            user: {
                id: updatedUser._id,
                username: updatedUser.username,
                displayName: updatedUser.displayName,
                avatar: updatedUser.avatar,
                bio: updatedUser.bio
            }
        });

    } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({ success: false, error: 'Failed to update profile' });
    }
});

// Notification Routes
app.get('/api/notifications', authenticate, async (req, res) => {
    try {
        const notifications = await db.collection('notifications').find({
            userId: req.user._id
        })
        .sort({ createdAt: -1 })
        .limit(50)
        .toArray();

        await db.collection('notifications').updateMany(
            { userId: req.user._id, isRead: false },
            { $set: { isRead: true } }
        );

        res.json({
            success: true,
            notifications
        });

    } catch (error) {
        console.error('Get notifications error:', error);
        res.status(500).json({ success: false, error: 'Failed to get notifications' });
    }
});

// Search Routes
app.get('/api/search', authenticate, async (req, res) => {
    try {
        const { q, type = 'all' } = req.query;

        if (!q || q.length < 2) {
            return res.json({ success: false, error: 'Search query too short' });
        }

        let users = [];
        let tweets = [];

        if (type === 'all' || type === 'users') {
            users = await db.collection('users').find({
                $or: [
                    { username: { $regex: q, $options: 'i' } },
                    { displayName: { $regex: q, $options: 'i' } }
                ]
            })
            .limit(10)
            .toArray();
        }

        if (type === 'all' || type === 'tweets') {
            tweets = await db.collection('tweets').find({
                content: { $regex: q, $options: 'i' }
            })
            .sort({ createdAt: -1 })
            .limit(20)
            .toArray();
        }

        res.json({
            success: true,
            users: users.map(user => ({
                id: user._id,
                username: user.username,
                displayName: user.displayName,
                avatar: user.avatar,
                followersCount: user.followersCount
            })),
            tweets
        });

    } catch (error) {
        console.error('Search error:', error);
        res.status(500).json({ success: false, error: 'Search failed' });
    }
});

// ===== HELPER FUNCTIONS =====
function extractHashtags(text) {
    const hashtags = text.match(/#\w+/g) || [];
    return [...new Set(hashtags)];
}

function extractMentions(text) {
    const mentions = text.match(/@\w+/g) || [];
    return [...new Set(mentions)];
}

async function createNotification(userId, type, fromUserId, tweetId = null) {
    try {
        await db.collection('notifications').insertOne({
            userId: userId,
            type: type,
            fromUserId: fromUserId,
            tweetId: tweetId,
            isRead: false,
            createdAt: new Date()
        });
    } catch (error) {
        console.error('Create notification error:', error);
    }
}

// Serve Frontend - FIXED: Serve from current directory
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Error Handling
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
});

app.use((req, res) => {
    res.status(404).json({ success: false, error: 'Endpoint not found' });
});

// Start Server
async function startServer() {
    await connectDB();
    
    app.listen(CONFIG.PORT, () => {
        console.log(`
Zetter Server Started
Port: ${CONFIG.PORT}
Database: MongoDB Atlas
OTP: ${CONFIG.SMTP_USER ? 'Enabled' : 'Development mode'}
Ready to tweet!
        `);
    });

    process.on('SIGTERM', async () => {
        console.log('SIGTERM received, shutting down gracefully');
        await client.close();
        process.exit(0);
    });
}

startServer().catch(console.error);