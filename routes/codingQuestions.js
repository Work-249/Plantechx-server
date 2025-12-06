const express = require('express');
const router = express.Router();
const multer = require('multer');
const csvParser = require('csv-parser');
const AdmZip = require('adm-zip');
const { Readable } = require('stream');
const { auth, authorize } = require('../middleware/auth');
const CodingQuestion = require('../models/CodingQuestion');
const CodingTestCase = require('../models/CodingTestCase');
const logger = require('../middleware/logger');

const upload = multer({
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  }
});

// Bulk upload coding questions
const processQuestionsBuffer = async (buffer, filename) => {
  let questions = [];
  if (filename.endsWith('.json')) {
    const jsonContent = buffer.toString();
    questions = JSON.parse(jsonContent);
    if (!Array.isArray(questions)) questions = [questions];
  } else if (filename.endsWith('.csv')) {
    questions = [];
    await new Promise((resolve, reject) => {
      const stream = Readable.from(buffer.toString());
      stream
        .pipe(csvParser())
        .on('data', (row) => {
          const question = {
            title: row.title,
            description: row.description,
            difficulty: row.difficulty?.toLowerCase() || 'medium',
            constraints: row.constraints,
            input_format: row.input_format,
            output_format: row.output_format,
            sample_input: row.sample_input,
            sample_output: row.sample_output,
            explanation: row.explanation,
            tags: row.tags?.split(',').map(tag => tag.trim()) || [],
            time_limit: parseInt(row.time_limit) || 3000,
            memory_limit: parseInt(row.memory_limit) || 512,
            test_cases: []
          };
          if (row.test_cases) {
            try { question.test_cases = JSON.parse(row.test_cases); } catch (e) { }
          }
          questions.push(question);
        })
        .on('end', resolve)
        .on('error', reject);
    });
  }
  return questions;
};

router.post('/import', auth, authorize('master_admin'), upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Please upload a file' });

  try {
    let allQuestions = [];

    if (req.file.originalname.endsWith('.zip')) {
      const zip = new AdmZip(req.file.buffer);
      const zipEntries = zip.getEntries();
      for (const entry of zipEntries) {
        if (entry.entryName.endsWith('.json') || entry.entryName.endsWith('.csv')) {
          const buf = entry.getData();
          const qs = await processQuestionsBuffer(buf, entry.entryName);
          allQuestions = allQuestions.concat(qs);
        }
      }
    } else {
      allQuestions = await processQuestionsBuffer(req.file.buffer, req.file.originalname);
    }

    // Validate and save questions (reuse existing flow)
    const results = { total: allQuestions.length, successful: 0, failed: 0, errors: [] };

    for (const q of allQuestions) {
      try {
        if (!q.title || !q.description) throw new Error('Title and description are required');

        const question = new CodingQuestion({
          title: q.title,
          description: q.description,
          difficulty: q.difficulty || 'medium',
          constraints: q.constraints,
          input_format: q.input_format,
          output_format: q.output_format,
          sample_input: q.sample_input,
          sample_output: q.sample_output,
          explanation: q.explanation,
          tags: q.tags || [],
          time_limit: q.time_limit || 3000,
          memory_limit: q.memory_limit || 512,
          created_by: req.user.id
        });

        await question.save();

        if (q.test_cases && Array.isArray(q.test_cases)) {
          const testCases = q.test_cases.map(tc => ({
            question_id: question._id,
            input: tc.input,
            expected_output: tc.expected_output,
            is_sample: tc.is_sample || false,
            weight: tc.weight || 1
          }));
          await CodingTestCase.insertMany(testCases);
        }

        results.successful++;
      } catch (error) {
        results.failed++;
        results.errors.push({ title: q.title || 'Unknown', error: error.message });
      }
    }

    return res.json({ message: 'Import completed', results });
  } catch (error) {
    logger.errorLog(error, { context: 'Import coding questions error' });
    return res.status(500).json({ error: 'Failed to import' });
  }
});

// Keep legacy bulk-upload route for backwards compatibility
router.post('/bulk-upload', auth, authorize('master_admin'), upload.single('file'), async (req, res) => {
  // delegate to /import handler
  req.url = '/import';
  return router.handle(req, res);
});
 
// Get coding question by ID with test cases
router.get('/:id/edit', auth, authorize('master_admin', 'college_admin'), async (req, res) => {
  try {
    const question = await CodingQuestion.findById(req.params.id);
    if (!question) {
      return res.status(404).json({ error: 'Question not found' });
    }

    const testCases = await CodingTestCase.find({ question_id: question._id });

    res.json({
      question: {
        id: question._id,
        title: question.title,
        description: question.description,
        difficulty: question.difficulty,
        constraints: question.constraints,
        input_format: question.input_format,
        output_format: question.output_format,
        sample_input: question.sample_input,
        sample_output: question.sample_output,
        explanation: question.explanation,
        tags: question.tags,
        time_limit: question.time_limit,
        memory_limit: question.memory_limit
      },
      testCases: testCases.map(tc => ({
        id: tc._id,
        input: tc.input,
        expected_output: tc.expected_output,
        is_sample: tc.is_sample,
        weight: tc.weight
      }))
    });
  } catch (error) {
    logger.errorLog(error, { context: 'Get coding question error' });
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;