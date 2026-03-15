const User = require('../models/User'); // Updated to match the new file name
const bcrypt = require('bcryptjs'); 
const jwt = require('jsonwebtoken');
const { validationResult } = require('express-validator');

exports.register = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  // Note: Your signup form uses 'username', not 'name', so I updated it here.
  const { username, email, password } = req.body; 

  try {
    // MongoDB uses findOne instead of your old custom findByEmail
    const existingUser = await User.findOne({ email }); 
    if (existingUser) return res.status(400).json({ message: 'Email already in use' });

    const hashedPassword = await bcrypt.hash(password, 10);
    
    // MongoDB uses create instead of your old custom createUser
    await User.create({
        username, // Make sure this matches your schema
        email, 
        password: hashedPassword
    });

    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
};

exports.login = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });

    // Handle users who signed up with Google (they don't have a password)
    if (!user.password) return res.status(400).json({ message: 'Please login with Google' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    // MongoDB uses _id instead of id
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
};