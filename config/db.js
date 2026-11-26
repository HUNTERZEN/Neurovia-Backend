const mongoose = require('mongoose');
const { MONGO_URI } = require('./env');

async function connectDB() {
  if (!MONGO_URI) {
    throw new Error('MONGO_URI environment variable is not configured.');
  }

  mongoose.set('strictQuery', true);

  await mongoose.connect(MONGO_URI, {
    serverSelectionTimeoutMS: 10000,
  });

  console.log('Connected to MongoDB database');
}

module.exports = connectDB;
