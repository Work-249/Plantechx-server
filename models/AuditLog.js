const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  actorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  action: { type: String, required: true },
  details: { type: mongoose.Schema.Types.Mixed },
  ip: String
}, { timestamps: true });

module.exports = mongoose.model('AuditLog', auditLogSchema);
