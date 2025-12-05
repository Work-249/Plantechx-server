const mongoose = require('mongoose');

const pendingActionSchema = new mongoose.Schema({
  type: { type: String, required: true }, // e.g., 'email_change'
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  newEmail: { type: String, required: true },
  token: { type: String, required: true, index: true },
  expiresAt: { type: Date, required: true },
  consumed: { type: Boolean, default: false }
}, { timestamps: true });

pendingActionSchema.index({ token: 1, expiresAt: 1 });

module.exports = mongoose.model('PendingAction', pendingActionSchema);
