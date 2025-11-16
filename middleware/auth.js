const jwt = require('jsonwebtoken');
const User = require('../models/User');
const logger = require('./logger');

const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      logger.warn('Authentication failed - no token provided', { 
        ip: req.ip, 
        url: req.url 
      });
      return res.status(401).json({ error: 'No token, authorization denied' });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id).populate('collegeId');
    
    if (!user || !user.isActive) {
      logger.warn('Authentication failed - user not found or inactive', { 
        userId: decoded.id,
        ip: req.ip 
      });
      return res.status(401).json({ error: 'User not found or inactive' });
    }
    
    req.user = user;
    logger.debug('Authentication successful', { 
      userId: user._id, 
      role: user.role,
      url: req.url 
    });
    next();
  } catch (error) {
    logger.warn('Authentication failed - invalid token', { 
      error: error.message,
      ip: req.ip 
    });
    res.status(401).json({ error: 'Token is not valid' });
  }
};

const authorize = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      logger.warn('Authorization failed - insufficient permissions', {
        userId: req.user._id,
        userRole: req.user.role,
        requiredRoles: roles,
        url: req.url
      });
      return res.status(403).json({ 
        error: 'Access denied. Insufficient permissions.' 
      });
    }
    logger.debug('Authorization successful', {
      userId: req.user._id,
      role: req.user.role,
      url: req.url
    });
    next();
  };
};

const collegeAccess = async (req, res, next) => {
  try {
    if (req.user.role === 'master_admin') {
      logger.debug('College access granted - master admin', { userId: req.user._id });
      return next();
    }
    
    // For college admin, faculty, and students - check college access
    const requestedCollegeId = req.params.collegeId || req.body.collegeId;
    
    if (requestedCollegeId && requestedCollegeId !== req.user.collegeId?.toString()) {
      logger.warn('College access denied - different college', {
        userId: req.user._id,
        userCollegeId: req.user.collegeId?.toString(),
        requestedCollegeId
      });
      return res.status(403).json({ 
        error: 'Access denied. You can only access your college data.' 
      });
    }
    
    logger.debug('College access granted', { 
      userId: req.user._id, 
      collegeId: req.user.collegeId 
    });
    next();
  } catch (error) {
    logger.errorLog(error, { context: 'College Access Check', userId: req.user?._id });
    res.status(500).json({ error: 'Server error during authorization' });
  }
};

module.exports = { auth, authorize, collegeAccess };