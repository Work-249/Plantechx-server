const express = require('express');
const router = express.Router();
const Subject = require('../models/Subject');
const { auth, authorize } = require('../middleware/auth');
const logger = require('../middleware/logger');

// Create or add a topic to a subject (subject param is subject name)
router.post('/:name/topics', auth, authorize('master_admin'), async (req, res) => {
  try {
    const subjectName = req.params.name;
    const { topic } = req.body;
    if (!topic || !topic.trim()) return res.status(400).json({ error: 'Topic is required' });

    let subject = await Subject.findOne({ name: subjectName });
    if (!subject) {
      subject = new Subject({ name: subjectName, topics: [topic.trim()] });
    } else {
      if (!subject.topics.includes(topic.trim())) {
        subject.topics.push(topic.trim());
      }
    }

    await subject.save();

    res.json({ message: 'Topic added', topic, topics: subject.topics });
  } catch (error) {
    logger.errorLog(error, { context: 'Add topic error' });
    res.status(500).json({ error: 'Server error' });
  }
});

// Get topics for a subject
router.get('/:name/topics', auth, authorize('master_admin'), async (req, res) => {
  try {
    const subjectName = req.params.name;
    const subject = await Subject.findOne({ name: subjectName });
    res.json({ topics: subject ? subject.topics : [] });
  } catch (error) {
    logger.errorLog(error, { context: 'Get topics error' });
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
