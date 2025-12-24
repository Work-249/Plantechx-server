const User = require('../models/User');
const logger = require('./logger');

const auth = async (req, res, next) => {
  try {
    console.log('[AUTH] Starting authentication', { method: req.method, url: req.url });
    
    if (!req.session || !req.session.user) {
      console.log('[AUTH] No session found', { method: req.method, url: req.url });
      logger.warn('Authentication failed - no session provided', { 
        ip: req.ip, 
        url: req.url 
      });
      return res.status(401).json({ error: 'Session expired or not found. Please log in.' });
    }
    
    const userId = req.session.user.id;
    console.log('[AUTH] Session found, looking up user...', { userId, method: req.method, url: req.url });
    
    const user = await User.findById(userId).populate('collegeId');
    if (!user || !user.isActive) {
      console.log('[AUTH] User not found or inactive', { userId, found: !!user, isActive: user?.isActive });
      logger.warn('Authentication failed - user not found or inactive', { 
        userId,
        ip: req.ip 
      });
      return res.status(401).json({ error: 'User not found or inactive' });
    }
    
    req.user = user;
    console.log('[AUTH] Authentication successful', { 
      userId: user._id,
      userName: user.name,
      userRole: user.role,
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
    logger.errorLog(error, { context: 'Auth Middleware', ip: req.ip });
    res.status(401).json({ error: 'Authentication failed' });
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