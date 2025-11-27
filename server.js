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
import 'dotenv/config';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Configuration - Only use environment variables
const CONFIG = {
    MONGODB_URI: process.env.MONGODB_URI,
    JWT_SECRET: process.env.JWT_SECRET || "fallback_secret_change_in_production_2024",
    PORT: process.env.PORT || 3000,
    SMTP_HOST: process.env.SMTP_HOST || "smtp.gmail.com",
    SMTP_PORT: process.env.SMTP_PORT || 587,
    SMTP_USER: process.env.SMTP_USER,
    SMTP_PASS: process.env.SMTP_PASS,
    NODE_ENV: process.env.NODE_ENV || 'development'
};

// Validate required environment variables
const requiredEnvVars = ['MONGODB_URI', 'JWT_SECRET'];
for (const envVar of requiredEnvVars) {
    if (!process.env[envVar]) {
        console.error(`❌ Missing required environment variable: ${envVar}`);
        if (CONFIG.NODE_ENV === 'production') {
            process.exit(1);
        } else {
            console.log('⚠️  Running in development mode with fallback values');
        }
    }
}

// Initialize Express
const app = express();

// Trust proxy for Render
app.set('trust proxy', 1);

// Security Middleware
app.use(helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
    contentSecurityPolicy: false
}));
app.use(compression());
app.use(cors({
    origin: ['http://localhost:3000', 'https://zetter-x.onrender.com', 'https://zetter-xmn.onrender.com'],
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, '.')));

// Rate Limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.'
});
app.use(limiter);

// Database Connection
let db, client;

async function connectDB() {
    try {
        console.log('🔄 Connecting to MongoDB...');
        client = new MongoClient(CONFIG.MONGODB_URI, {
            serverApi: { 
                version: ServerApiVersion.v1, 
                strict: true, 
                deprecationErrors: true 
            },
            maxPoolSize: 50,
            retryWrites: true,
            w: 'majority'
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
        await db.collection('otps').createIndex({ expires: 1 }, { expireAfterSeconds: 0 });
        
        console.log('✅ MongoDB Connected Successfully');
        
        // Create admin user if not exists
        await createAdminUser();
        
    } catch (error) {
        console.error('❌ MongoDB connection failed:', error);
        if (CONFIG.NODE_ENV === 'production') {
            process.exit(1);
        }
    }
}

async function createAdminUser() {
    try {
        const adminExists = await db.collection('users').findOne({ username: 'admin' });
        if (!adminExists) {
            const hashedPassword = await bcrypt.hash('admin123', 12);
            await db.collection('users').insertOne({
                username: 'admin',
                email: 'admin@zetter.com',
                password: hashedPassword,
                displayName: 'Administrator',
                bio: 'System Administrator',
                avatar: '👑',
                isVerified: true,
                followersCount: 0,
                followingCount: 0,
                tweetsCount: 0,
                joinedDate: new Date(),
                role: 'admin'
            });
            console.log('✅ Admin user created');
        }
    } catch (error) {
        console.error('❌ Failed to create admin user:', error);
    }
}

// Utility Functions
function generateToken(user) {
    return jwt.sign(
        { 
            userId: user._id.toString(), 
            username: user.username, 
            role: user.role 
        },
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
            return res.status(401).json({ success: false, error: 'Authentication token required' });
        }

        const decoded = await verifyToken(token);
        if (!decoded) {
            return res.status(401).json({ success: false, error: 'Invalid or expired token' });
        }

        const user = await db.collection('users').findOne({ _id: new ObjectId(decoded.userId) });
        if (!user) {
            return res.status(401).json({ success: false, error: 'User not found' });
        }

        req.user = user;
        next();
    } catch (error) {
        console.error('Authentication error:', error);
        res.status(401).json({ success: false, error: 'Authentication failed' });
    }
}

// Input Validation Middleware
function validateSignup(req, res, next) {
    const { username, email, password, displayName } = req.body;
    
    if (!username || !email || !password || !displayName) {
        return res.status(400).json({ success: false, error: 'All fields are required' });
    }
    
    if (username.length < 3) {
        return res.status(400).json({ success: false, error: 'Username must be at least 3 characters' });
    }
    
    if (password.length < 6) {
        return res.status(400).json({ success: false, error: 'Password must be at least 6 characters' });
    }
    
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ success: false, error: 'Invalid email format' });
    }
    
    if (displayName.length < 2) {
        return res.status(400).json({ success: false, error: 'Display name must be at least 2 characters' });
    }
    
    next();
}

// OTP Email Service
async function sendOTP(email, otpCode) {
    try {
        // In development, log OTP instead of sending email
        if (!CONFIG.SMTP_USER || !CONFIG.SMTP_PASS || CONFIG.NODE_ENV === 'development') {
            console.log(`📧 OTP for ${email}: ${otpCode}`);
            return true;
        }

        const transporter = nodemailer.createTransport({
            host: CONFIG.SMTP_HOST,
            port: CONFIG.SMTP_PORT,
            secure: false,
            auth: {
                user: CONFIG.SMTP_USER,
                pass: CONFIG.SMTP_PASS
            }
        });

        await transporter.sendMail({
            from: `"Zetter" <${CONFIG.SMTP_USER}>`,
            to: email,
            subject: 'Verify Your Zetter Account',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #1DA1F2; text-align: center;">Zetter</h2>
                    <p>Hello,</p>
                    <p>Your verification code is:</p>
                    <h1 style="font-size: 32px; color: #1DA1F2; letter-spacing: 8px; text-align: center; margin: 20px 0;">
                        ${otpCode}
                    </h1>
                    <p>This code will expire in 10 minutes.</p>
                    <p>If you didn't request this, please ignore this email.</p>
                    <br>
                    <p>Best regards,<br>The Zetter Team</p>
                </div>
            `
        });

        console.log(`✅ OTP email sent to: ${email}`);
        return true;
    } catch (error) {
        console.error('❌ Email sending failed:', error);
        return false;
    }
}

// Helper Functions
function extractHashtags(text) {
    const hashtags = text.match(/#[\w\u0590-\u05ff]+/g) || [];
    return [...new Set(hashtags.map(tag => tag.toLowerCase()))];
}

function extractMentions(text) {
    const mentions = text.match(/@[\w]+/g) || [];
    return [...new Set(mentions.map(mention => mention.toLowerCase()))];
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
        console.error('Failed to create notification:', error);
    }
}

// ===== ROUTES =====

// Health Check
app.get('/health', async (req, res) => {
    try {
        await db.collection('users').findOne({});
        res.json({
            success: true,
            status: 'Healthy',
            version: '1.0.0',
            database: 'Connected',
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false, 
            status: 'Unhealthy', 
            error: error.message 
        });
    }
});

// User Registration
app.post('/api/auth/signup', validateSignup, async (req, res) => {
    try {
        const { username, email, password, displayName } = req.body;

        // Clean inputs
        const cleanUsername = username.toLowerCase().trim();
        const cleanEmail = email.toLowerCase().trim();
        const cleanDisplayName = displayName.trim();

        // Check for existing user
        const existingUser = await db.collection('users').findOne({
            $or: [
                { username: cleanUsername },
                { email: cleanEmail }
            ]
        });

        if (existingUser) {
            if (existingUser.username === cleanUsername) {
                return res.status(400).json({ success: false, error: 'Username already exists' });
            }
            if (existingUser.email === cleanEmail) {
                return res.status(400).json({ success: false, error: 'Email already registered' });
            }
        }

        // Generate OTP
        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpiry = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 12);

        // Create user
        const user = {
            username: cleanUsername,
            email: cleanEmail,
            password: hashedPassword,
            displayName: cleanDisplayName,
            bio: '',
            avatar: '👤',
            isVerified: false,
            followersCount: 0,
            followingCount: 0,
            tweetsCount: 0,
            joinedDate: new Date(),
            role: 'user'
        };

        const result = await db.collection('users').insertOne(user);
        const newUser = await db.collection('users').findOne({ _id: result.insertedId });

        // Store OTP
        await db.collection('otps').insertOne({
            userId: result.insertedId,
            email: cleanEmail,
            code: otpCode,
            expires: otpExpiry,
            attempts: 0,
            createdAt: new Date()
        });

        // Send OTP
        await sendOTP(email, otpCode);

        // Generate temporary token (limited access)
        const tempToken = generateToken(newUser);

        res.json({
            success: true,
            message: 'Registration successful! Check your email for verification code.',
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
        res.status(500).json({ 
            success: false, 
            error: 'Registration failed. Please try again.' 
        });
    }
});

// Verify OTP
app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const { email, otpCode } = req.body;

        if (!email || !otpCode) {
            return res.status(400).json({ success: false, error: 'Email and OTP code are required' });
        }

        const cleanEmail = email.toLowerCase().trim();

        // Find valid OTP
        const otpRecord = await db.collection('otps').findOne({
            email: cleanEmail,
            expires: { $gt: new Date() }
        });

        if (!otpRecord) {
            return res.status(400).json({ success: false, error: 'OTP expired or invalid' });
        }

        if (otpRecord.attempts >= 3) {
            await db.collection('otps').deleteOne({ _id: otpRecord._id });
            return res.status(400).json({ success: false, error: 'Too many attempts. Please request a new OTP.' });
        }

        if (otpRecord.code !== otpCode) {
            await db.collection('otps').updateOne(
                { _id: otpRecord._id },
                { $inc: { attempts: 1 } }
            );
            return res.status(400).json({ success: false, error: 'Invalid OTP code' });
        }

        // OTP is valid - verify user
        await db.collection('users').updateOne(
            { _id: otpRecord.userId },
            { $set: { isVerified: true } }
        );

        // Remove used OTP
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
                followingCount: user.followingCount,
                bio: user.bio
            }
        });

    } catch (error) {
        console.error('OTP verification error:', error);
        res.status(500).json({ success: false, error: 'Verification failed' });
    }
});

// Resend OTP
app.post('/api/auth/resend-otp', async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ success: false, error: 'Email is required' });
        }

        const cleanEmail = email.toLowerCase().trim();
        const user = await db.collection('users').findOne({ email: cleanEmail });

        if (!user) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }

        if (user.isVerified) {
            return res.status(400).json({ success: false, error: 'Email already verified' });
        }

        // Generate new OTP
        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpiry = new Date(Date.now() + 10 * 60 * 1000);

        // Remove old OTPs
        await db.collection('otps').deleteMany({ email: cleanEmail });

        // Store new OTP
        await db.collection('otps').insertOne({
            userId: user._id,
            email: cleanEmail,
            code: otpCode,
            expires: otpExpiry,
            attempts: 0,
            createdAt: new Date()
        });

        // Send OTP
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

// User Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ success: false, error: 'Username and password are required' });
        }

        const cleanUsername = username.toLowerCase().trim();
        const user = await db.collection('users').findOne({
            username: cleanUsername
        });

        if (!user) {
            return res.status(401).json({ success: false, error: 'Invalid username or password' });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ success: false, error: 'Invalid username or password' });
        }

        if (!user.isVerified) {
            return res.status(403).json({ 
                success: false, 
                error: 'Please verify your email first', 
                needsVerification: true,
                email: user.email
            });
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
                bio: user.bio,
                tweetsCount: user.tweetsCount,
                joinedDate: user.joinedDate
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, error: 'Login failed' });
    }
});

// Get Current User
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
                joinedDate: req.user.joinedDate,
                role: req.user.role
            }
        });
    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({ success: false, error: 'Failed to get user data' });
    }
});

// Get User Suggestions
app.get('/api/users/suggestions', authenticate, async (req, res) => {
    try {
        // Get users that current user follows
        const following = await db.collection('follows').find({
            followerId: req.user._id
        }).toArray();

        const followingIds = following.map(f => f.followingId);
        followingIds.push(req.user._id); // Exclude self

        // Get random users (excluding current user and already followed)
        const suggestions = await db.collection('users').aggregate([
            { 
                $match: { 
                    _id: { $nin: followingIds },
                    isVerified: true
                } 
            },
            { $sample: { size: 5 } },
            { 
                $project: {
                    _id: 1,
                    displayName: 1,
                    username: 1,
                    avatar: 1,
                    bio: 1,
                    followersCount: 1,
                    isVerified: 1
                }
            }
        ]).toArray();

        res.json({
            success: true,
            users: suggestions
        });

    } catch (error) {
        console.error('Suggestions error:', error);
        res.status(500).json({ success: false, error: 'Failed to load suggestions' });
    }
});

// Create Tweet
app.post('/api/tweets', authenticate, async (req, res) => {
    try {
        const { content, replyTo } = req.body;

        if (!content || content.trim().length === 0) {
            return res.status(400).json({ success: false, error: 'Tweet content cannot be empty' });
        }

        if (content.length > 280) {
            return res.status(400).json({ success: false, error: 'Tweet cannot exceed 280 characters' });
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

        // Update user's tweet count
        await db.collection('users').updateOne(
            { _id: req.user._id },
            { $inc: { tweetsCount: 1 } }
        );

        // Create notifications for mentions
        for (const mention of tweet.mentions) {
            const mentionedUsername = mention.slice(1); // Remove @
            const mentionedUser = await db.collection('users').findOne({ username: mentionedUsername });
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

// Get Home Timeline
app.get('/api/tweets/timeline', authenticate, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = Math.min(parseInt(req.query.limit) || 20, 50); // Max 50 per page

        // Get users that current user follows
        const following = await db.collection('follows').find({
            followerId: req.user._id
        }).toArray();

        const followingIds = following.map(f => f.followingId);
        followingIds.push(req.user._id); // Include own tweets

        const tweets = await db.collection('tweets').find({
            userId: { $in: followingIds },
            replyTo: null // Exclude replies from main timeline
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

// Get Tweet by ID
app.get('/api/tweets/:id', authenticate, async (req, res) => {
    try {
        if (!ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ success: false, error: 'Invalid tweet ID' });
        }

        const tweet = await db.collection('tweets').findOne({
            _id: new ObjectId(req.params.id)
        });

        if (!tweet) {
            return res.status(404).json({ success: false, error: 'Tweet not found' });
        }

        // Increment view count
        await db.collection('tweets').updateOne(
            { _id: tweet._id },
            { $inc: { viewCount: 1 } }
        );

        // Get replies
        const replies = await db.collection('tweets').find({
            replyTo: req.params.id
        })
        .sort({ createdAt: 1 })
        .limit(50)
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

// Like/Unlike Tweet
app.post('/api/tweets/:id/like', authenticate, async (req, res) => {
    try {
        if (!ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ success: false, error: 'Invalid tweet ID' });
        }

        const tweet = await db.collection('tweets').findOne({
            _id: new ObjectId(req.params.id)
        });

        if (!tweet) {
            return res.status(404).json({ success: false, error: 'Tweet not found' });
        }

        const userIdStr = req.user._id.toString();
        const hasLiked = tweet.likes.includes(userIdStr);

        if (hasLiked) {
            // Unlike
            await db.collection('tweets').updateOne(
                { _id: tweet._id },
                { 
                    $pull: { likes: userIdStr },
                    $inc: { likesCount: -1 }
                }
            );
        } else {
            // Like
            await db.collection('tweets').updateOne(
                { _id: tweet._id },
                { 
                    $addToSet: { likes: userIdStr },
                    $inc: { likesCount: 1 }
                }
            );

            // Create notification (if not own tweet)
            if (tweet.userId.toString() !== userIdStr) {
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

// Follow/Unfollow User
app.post('/api/users/:username/follow', authenticate, async (req, res) => {
    try {
        const targetUser = await db.collection('users').findOne({
            username: req.params.username.toLowerCase()
        });

        if (!targetUser) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }

        if (targetUser._id.toString() === req.user._id.toString()) {
            return res.status(400).json({ success: false, error: 'Cannot follow yourself' });
        }

        const isFollowing = await db.collection('follows').findOne({
            followerId: req.user._id,
            followingId: targetUser._id
        });

        if (isFollowing) {
            // Unfollow
            await db.collection('follows').deleteOne({
                followerId: req.user._id,
                followingId: targetUser._id
            });

            // Update counts
            await db.collection('users').updateOne(
                { _id: req.user._id },
                { $inc: { followingCount: -1 } }
            );
            await db.collection('users').updateOne(
                { _id: targetUser._id },
                { $inc: { followersCount: -1 } }
            );

        } else {
            // Follow
            await db.collection('follows').insertOne({
                followerId: req.user._id,
                followingId: targetUser._id,
                createdAt: new Date()
            });

            // Update counts
            await db.collection('users').updateOne(
                { _id: req.user._id },
                { $inc: { followingCount: 1 } }
            );
            await db.collection('users').updateOne(
                { _id: targetUser._id },
                { $inc: { followersCount: 1 } }
            );

            // Create notification
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

// Get User Profile
app.get('/api/users/:username', authenticate, async (req, res) => {
    try {
        const user = await db.collection('users').findOne({
            username: req.params.username.toLowerCase()
        });

        if (!user) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }

        // Check if current user follows this user
        const isFollowing = await db.collection('follows').findOne({
            followerId: req.user._id,
            followingId: user._id
        });

        // Get user's tweets
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

// Update User Profile
app.put('/api/users/profile', authenticate, async (req, res) => {
    try {
        const { displayName, bio, avatar } = req.body;

        const updateData = {};
        if (displayName && displayName.trim().length >= 2) {
            updateData.displayName = displayName.trim();
        }
        if (bio !== undefined) {
            updateData.bio = bio.trim();
        }
        if (avatar) {
            updateData.avatar = avatar;
        }

        if (Object.keys(updateData).length === 0) {
            return res.status(400).json({ success: false, error: 'No valid fields to update' });
        }

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

// Get Notifications
app.get('/api/notifications', authenticate, async (req, res) => {
    try {
        const notifications = await db.collection('notifications').find({
            userId: req.user._id
        })
        .sort({ createdAt: -1 })
        .limit(50)
        .toArray();

        // Mark as read
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

// Search Users and Tweets
app.get('/api/search', authenticate, async (req, res) => {
    try {
        const { q, type = 'all' } = req.query;

        if (!q || q.trim().length < 2) {
            return res.status(400).json({ success: false, error: 'Search query must be at least 2 characters' });
        }

        const searchQuery = q.trim();
        let users = [];
        let tweets = [];

        if (type === 'all' || type === 'users') {
            users = await db.collection('users').find({
                $or: [
                    { username: { $regex: searchQuery, $options: 'i' } },
                    { displayName: { $regex: searchQuery, $options: 'i' } }
                ],
                isVerified: true
            })
            .limit(10)
            .toArray();
        }

        if (type === 'all' || type === 'tweets') {
            tweets = await db.collection('tweets').find({
                content: { $regex: searchQuery, $options: 'i' }
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
                followersCount: user.followersCount,
                isVerified: user.isVerified
            })),
            tweets
        });

    } catch (error) {
        console.error('Search error:', error);
        res.status(500).json({ success: false, error: 'Search failed' });
    }
});

// Serve Frontend
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Error Handling Middleware
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    res.status(500).json({ 
        success: false, 
        error: 'Internal server error',
        ...(CONFIG.NODE_ENV === 'development' && { stack: error.stack })
    });
});

// 404 Handler
app.use((req, res) => {
    res.status(404).json({ success: false, error: 'Endpoint not found' });
});

// Start Server
async function startServer() {
    try {
        await connectDB();
        
        app.listen(CONFIG.PORT, () => {
            console.log(`
🐦 Zetter Server Started Successfully!
📍 Port: ${CONFIG.PORT}
🌍 Environment: ${CONFIG.NODE_ENV}
🗃️  Database: MongoDB Atlas
📧 OTP: ${CONFIG.SMTP_USER ? 'Enabled' : 'Development Mode'}
🚀 Ready to serve requests!
            `);
        });

        // Graceful shutdown
        process.on('SIGTERM', async () => {
            console.log('SIGTERM received, shutting down gracefully...');
            if (client) {
                await client.close();
            }
            process.exit(0);
        });

    } catch (error) {
        console.error('❌ Failed to start server:', error);
        process.exit(1);
    }
}

startServer().catch(console.error);