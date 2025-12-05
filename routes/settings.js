const express = require('express');
const SiteConfig = require('../models/SiteConfig');
const { auth, authorize } = require('../middleware/auth');
const logger = require('../middleware/logger');

const router = express.Router();

// Get platform settings
router.get('/', async (req, res) => {
  try {
    const doc = await SiteConfig.findOne({ key: 'platform' });
    res.json(doc ? doc.value : { logo_url: '/assets/default-logo.svg' });
  } catch (error) {
    logger.errorLog(error, { context: 'Get settings error' });
    res.status(500).json({ error: 'Server error' });
  }
});

// Update platform settings (Master Admin only)
router.put('/', auth, authorize('master_admin'), async (req, res) => {
  try {
    const { logo_url, ...rest } = req.body;
    let doc = await SiteConfig.findOne({ key: 'platform' });
    const newValue = Object.assign({}, doc ? doc.value : {}, { ...rest });
    if (logo_url) newValue.logo_url = logo_url;

    if (doc) {
      doc.value = newValue;
      await doc.save();
    } else {
      doc = await SiteConfig.create({ key: 'platform', value: newValue });
    }

    res.json({ success: true, settings: doc.value });
  } catch (error) {
    logger.errorLog(error, { context: 'Update settings error' });
    res.status(500).json({ error: 'Server error' });
  }
});

// Upload platform logo - accepts form-data with field 'imageUrl' or JSON { logo_url }
router.post('/logo', auth, authorize('master_admin'), async (req, res) => {
  try {
    const imageUrl = req.body.imageUrl || req.body.logo_url || req.body.logoUrl;
    if (!imageUrl) return res.status(400).json({ error: 'imageUrl or logo_url required' });

    let doc = await SiteConfig.findOne({ key: 'platform' });
    const newValue = Object.assign({}, doc ? doc.value : {}, { logo_url: imageUrl });

    if (doc) {
      doc.value = newValue;
      await doc.save();
    } else {
      doc = await SiteConfig.create({ key: 'platform', value: newValue });
    }

    res.json({ success: true, imageUrl: imageUrl, settings: doc.value });
  } catch (error) {
    logger.errorLog(error, { context: 'Upload logo error' });
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
