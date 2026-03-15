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
  }
}, { 
  // Automatically adds createdAt and updatedAt timestamps
  timestamps: true 
});

const User = mongoose.model('User', userSchema);
module.exports = User;