const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  // In your old code you called it 'name', in your server.js you called it 'username'. 
  // Let's stick with 'username' to match your signup form.
  username: { 
    type: String, 
    required: true 
  },
  email: { 
    type: String, 
    required: true, 
    unique: true 
  },
  password: { 
    type: String, 
    // Not required because users who sign in with Google won't have a password!
    required: false 
  },
  google_id: { 
    type: String, 
    required: false,
    unique: true,
    // 'sparse' means MongoDB allows multiple users to have a 'null' google_id
    sparse: true 
  },
  // --- Additional Profile Fields ---
  fullName: { type: String },
  phone: { type: String },
  location: { type: String },
  profession: { type: String },
  company: { type: String },
  bio: { type: String },
  website: { type: String },
  github: { type: String },
  linkedin: { type: String },
  twitter: { type: String },
  profileImage: { type: String, default: '/api/placeholder/150/150' },
  joinDate: { 
    type: String,
    // Provide a default join year based on when the user is created
    default: () => new Date().getFullYear().toString()
  }
}, { 
  // Automatically adds createdAt and updatedAt timestamps
  timestamps: true 
});

const User = mongoose.model('User', userSchema);
module.exports = User;