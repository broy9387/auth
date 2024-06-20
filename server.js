const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');


const app = express();
const PORT = 3000;

app.use(bodyParser.json());

const users = []; // This should be replaced with a database in a real application

const secretKey = "kqDFcxgWLeAS6Oag8gazr9UABR4z9T6Xk/4jHZ0xM88="; // Load secret key from environment variable

// User registration with roles
app.post('/register', async (req, res) => {
  const { username, password, role } = req.body;

  if (!username || !password || !role) {
    return res.status(400).json({ message: 'Username, password, and role are required' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ username, password: hashedPassword, role });
  res.status(201).json({ message: 'User registered successfully' });
});

// User login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  const user = users.find(u => u.username === username);
  if (!user) {
    return res.status(400).json({ message: 'Invalid username or password' });
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(400).json({ message: 'Invalid username or password' });
  }

  const token = jwt.sign({ username, role: user.role }, secretKey, { expiresIn: '1h' });
  res.json({ token });
});

// Authentication middleware
const authenticateJWT = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1];

  if (!token) {
    return res.sendStatus(403);
  }

  try {
    const decoded = jwt.verify(token, secretKey);
    req.user = decoded;
    next();
  } catch (err) {
    res.sendStatus(403);
  }
};

// Authorization middleware
const authorizeRole = (role) => {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.sendStatus(403);
    }
    next();
  };
};

// Example protected route
app.get('/profile', authenticateJWT, (req, res) => {
  res.json({ message: `Hello, ${req.user.username}` });
});

// Example admin-only route
app.get('/admin', authenticateJWT, authorizeRole('admin'), (req, res) => {
  res.json({ message: 'Welcome, admin!' });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
