const mongoose = require('mongoose');

const bookingSchema = new mongoose.Schema(
  {
    bookingNumber: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: false,
    },
    customerName: {
      type: String,
      required: true,
      trim: true,
      maxlength: 120,
    },
    email: {
      type: String,
      required: true,
      lowercase: true,
      trim: true,
      maxlength: 254,
    },
    phone: {
      type: String,
      required: true,
      trim: true,
      maxlength: 30,
    },
    deviceType: {
      type: String,
      required: true,
      trim: true,
      maxlength: 80,
    },
    deviceBrand: {
      type: String,
      trim: true,
      maxlength: 120,
      default: '',
    },
    operatingSystem: {
      type: String,
      trim: true,
      maxlength: 80,
      default: '',
    },
    issueDescription: {
      type: String,
      required: true,
      trim: true,
      maxlength: 4000,
    },
    supportType: {
      type: String,
      enum: ['remote', 'onsite'],
      required: true,
    },
    preferredDate: {
      type: String,
      trim: true,
      maxlength: 40,
      default: '',
    },
    preferredTime: {
      type: String,
      trim: true,
      maxlength: 60,
      default: '',
    },
    attachmentNames: [{ type: String }],
    serviceId: { type: String, default: '' },
    amountInr: { type: Number, default: 0 },
    paymentStatus: {
      type: String,
      enum: ['pay_after_fix', 'pending', 'paid'],
      default: 'pay_after_fix',
    },
    razorpayOrderId: { type: String, default: '' },
    razorpayPaymentId: { type: String, default: '' },
    status: {
      type: String,
      enum: ['pending', 'assigned', 'in_progress', 'resolved', 'cancelled'],
      default: 'pending',
    },
  },
  { timestamps: true }
);

module.exports = mongoose.models.Booking || mongoose.model('Booking', bookingSchema);

