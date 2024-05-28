const http = require('http');
const url = require('url');
const querystring = require('querystring');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const fs = require('fs');
const PORT = 7000;

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/food_ordering');
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
    console.log('Connected to MongoDB');
});

// Define a schema for User
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

// Define a model for User
const User = mongoose.model('User', userSchema);

// Utility function to serve static files
function serveFile(res, filepath, contentType) {
    fs.readFile(filepath, (err, data) => {
        if (err) {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            res.end('File not found');
        } else {
            res.writeHead(200, { 'Content-Type': contentType });
            res.end(data);
        }
    });
}

// Utility function to parse request body
function parseBody(req, callback) {
    let body = '';
    req.on('data', chunk => {
        body += chunk.toString();
    });
    req.on('end', () => {
        callback(querystring.parse(body));
    });
}

// Create HTTP server
const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);
    const pathname = parsedUrl.pathname;

    // Serve static files
    if (req.method === 'GET' && pathname === '/') {
        serveFile(res, './public/index.html', 'text/html');
    } else if (req.method === 'POST' && pathname === '/signup') {
        // Handle signup
        parseBody(req, async (body) => {
            try {
                const { name, email, signup_username, signup_password, confirm_password } = body;

                // Check if passwords match
                if (signup_password !== confirm_password) {
                    res.writeHead(400, { 'Content-Type': 'text/plain' });
                    return res.end('Passwords do not match');
                }

                // Check if email or username already exists
                const existingUser = await User.findOne({ $or: [{ email }, { username: signup_username }] });
                if (existingUser) {
                    res.writeHead(409, { 'Content-Type': 'text/plain' });
                    return res.end('Email or Username already exists');
                }

                // Hash the password
                const hashedPassword = await bcrypt.hash(signup_password, 10);

                // Create a new User document
                const newUser = new User({
                    name,
                    email,
                    username: signup_username,
                    password: hashedPassword
                });

                // Save the new User document to MongoDB
                await newUser.save();

                // Send response to client
                res.writeHead(200, { 'Content-Type': 'text/plain' });
                res.end('User registered successfully!');
            } catch (error) {
                console.error('Error signing up:', error);
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end(`Error registering user: ${error.message}`);
            }
        });
    } else if (req.method === 'POST' && pathname === '/login') {
        // Handle login
        parseBody(req, async (body) => {
            try {
                const { username, password } = body;

                // Check if a user with the provided username exists in the database
                const user = await User.findOne({ username });
                if (!user) {
                    res.writeHead(404, { 'Content-Type': 'text/plain' });
                    return res.end('User not found');
                }

                // Check if the password matches the password stored in the database
                const isPasswordCorrect = await bcrypt.compare(password, user.password);
                if (!isPasswordCorrect) {
                    res.writeHead(401, { 'Content-Type': 'text/plain' });
                    return res.end('Incorrect password');
                }

                // If username and password are correct, send success response
                res.writeHead(200, { 'Content-Type': 'text/plain' });
                res.end('Login successful!');
            } catch (error) {
                console.error('Error logging in:', error);
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end('Error logging in');
            }
        });
    } else {
        // Handle 404 Not Found
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found');
    }
});

// Start the server
server.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
