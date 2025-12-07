const jwt = require('jsonwebtoken');
const User = require('../models/User');
const logger = require('./logger');

const auth = async (req, res, next) => {
  try {
    console.log('[AUTH] Starting authentication', { method: req.method, url: req.url });
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      console.log('[AUTH] No token provided', { method: req.method, url: req.url });
      logger.warn('Authentication failed - no token provided', { 
        ip: req.ip, 
        url: req.url 
      });
      return res.status(401).json({ error: 'No token, authorization denied' });
    }
    
    console.log('[AUTH] Token found, verifying...', { method: req.method, url: req.url });
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log('[AUTH] Token verified, looking up user...', { decodedId: decoded.id, method: req.method, url: req.url });
    const user = await User.findById(decoded.id).populate('collegeId');
    
    if (!user || !user.isActive) {
      console.log('[AUTH] User not found or inactive', { userId: decoded.id, found: !!user, isActive: user?.isActive });
      logger.warn('Authentication failed - user not found or inactive', { 
        userId: decoded.id,
        ip: req.ip 
      });
      return res.status(401).json({ error: 'User not found or inactive' });
    }
    
    req.user = user;
    console.log('[AUTH] Authentication successful', { 
      userId: user._id,
      userName: user.name,
      userRole: user.role,
      userRoleType: typeof user.role,
      roleCharCodes: user.role.split('').map(c => c.charCodeAt(0)),
      url: req.url,
      method: req.method
    });
    logger.debug('Authentication successful', { 
      userId: user._id, 
      role: user.role,
      url: req.url 
    });
    next();
  } catch (error) {
    console.log('[AUTH] Authentication failed with error', { 
      error: error.message, 
      method: req.method, 
      url: req.url 
    });
    logger.warn('Authentication failed - invalid token', { 
      error: error.message,
      ip: req.ip 
    });
    res.status(401).json({ error: 'Token is not valid' });
  }
};

const authorize = (...roles) => {
  return (req, res, next) => {
    console.log('[AUTHORIZE] Checking authorization', {
      userRole: req.user.role,
      requiredRoles: roles,
      hasPermission: roles.includes(req.user.role),
      url: req.url
    });
    
    if (!roles.includes(req.user.role)) {
      console.log('[AUTHORIZE] Authorization DENIED', {
        userId: req.user._id,
        userRole: req.user.role,
        requiredRoles: roles,
        url: req.url
      });
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
    console.log('[AUTHORIZE] Authorization GRANTED', {
      userId: req.user._id,
      role: req.user.role,
      url: req.url
    });
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