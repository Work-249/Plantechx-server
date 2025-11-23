const mongoose = require('mongoose');
const logger = require('../middleware/logger');

const connectDB = async () => {
  try {
    logger.info('Attempting to connect to MongoDB', {
      uri: process.env.MONGODB_URI ? 'URI provided' : 'URI missing'
    });

    const conn = await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });

    logger.info('MongoDB Connected Successfully', {
      host: conn.connection.host,
      database: conn.connection.name,
      port: conn.connection.port
    });

    // Create master admin if it doesn't exist
    await createMasterAdmin();

    // Return the mongoose connection for callers to await
    return conn;
  } catch (error) {
    // Log full error including stack so platform logs capture the cause
    logger.errorLog(error, { context: 'Database Connection' });
    // Re-throw the error so callers can handle it (do not exit here)
    throw error;
  }
};

const createMasterAdmin = async () => {
  try {
    logger.info('Checking for Master Admin user');
    
    const User = require('../models/User');
    
    const masterAdmin = await User.findOne({ role: 'master_admin' });
    
    if (!masterAdmin) {
      logger.info('Creating Master Admin user');
      
      const newMasterAdmin = new User({
        name: process.env.MASTER_ADMIN_NAME || 'Master Administrator',
        email: process.env.MASTER_ADMIN_EMAIL,
        password: process.env.MASTER_ADMIN_PASSWORD,
        role: 'master_admin'
      });

      if (!process.env.MASTER_ADMIN_EMAIL || !process.env.MASTER_ADMIN_PASSWORD) {
        throw new Error('MASTER_ADMIN_EMAIL and MASTER_ADMIN_PASSWORD must be set in environment variables');
      }
      
      await newMasterAdmin.save();
      
      logger.info('Master Admin Created Successfully', {
        email: process.env.MASTER_ADMIN_EMAIL,
        hasDefaultPassword: true
      });
    } else {
      logger.info('Master Admin already exists', {
        email: masterAdmin.email,
        hasLoggedIn: masterAdmin.hasLoggedIn
      });
    }
  } catch (error) {
    logger.errorLog(error, { context: 'Master Admin Creation' });
  }
};

module.exports = connectDB;
