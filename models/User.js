const mongoose = require('mongoose');

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      trim: true,
      maxlength: 64,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      maxlength: 254,
    },
    password: {
      type: String,
      required: false,
    },
    google_id: {
      type: String,
      required: false,
      unique: true,
      sparse: true,
    },
    role: {
      type: String,
      enum: ['user', 'partner', 'technician', 'admin'],
      default: 'user',
    },
    status: {
      type: String,
      enum: ['active', 'inactive'],
      default: 'active',
    },
    welcomeEmailSent: {
      type: Boolean,
      default: false,
    },
    resetPasswordTokenHash: { type: String, select: false },
    resetPasswordExpires: { type: Date, select: false },
    // --- Additional Profile Fields ---
    fullName: { type: String, trim: true, maxlength: 120 },
    phone: { type: String, trim: true, maxlength: 30 },
    location: { type: String, trim: true, maxlength: 120 },
    profession: { type: String, trim: true, maxlength: 120 },
    company: { type: String, trim: true, maxlength: 120 },
    bio: { type: String, trim: true, maxlength: 1000 },
    website: { type: String, trim: true, maxlength: 255 },
    github: { type: String, trim: true, maxlength: 255 },
    linkedin: { type: String, trim: true, maxlength: 255 },
    twitter: { type: String, trim: true, maxlength: 255 },
    profileImage: { type: String, default: '/api/placeholder/150/150', maxlength: 500 },
    joinDate: {
      type: String,
      default: () => new Date().getFullYear().toString(),
    },
  },
  {
    timestamps: true,
  }
);

const User = mongoose.models.User || mongoose.model('User', userSchema);
module.exports = User;
