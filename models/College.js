const mongoose = require('mongoose');

const collegeSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  code: {
    type: String,
    required: true,
    unique: true,
    uppercase: true,
    trim: true
  },
 email: {
  type: String,
  required: true,
  unique: true,
  lowercase: true,
  trim: true
},
  address: {
    type: String,
    required: true,
    trim: true
  },
  adminId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  isActive: {
    type: Boolean,
    default: true
  },
  // Statistics
  totalFaculty: {
    type: Number,
    default: 0
  },
  totalStudents: {
    type: Number,
    default: 0
  }
}, {
  timestamps: true
});

// Update statistics when users are added/removed
collegeSchema.methods.updateStats = async function() {
  const User = require('./User');
  
  const facultyCount = await User.countDocuments({
    collegeId: this._id,
    role: 'faculty',
    isActive: true
  });
  
  const studentCount = await User.countDocuments({
    collegeId: this._id,
    role: 'student',
    isActive: true
  });
  
  this.totalFaculty = facultyCount;
  this.totalStudents = studentCount;
  
  await this.save();
};

module.exports = mongoose.model('College', collegeSchema);
