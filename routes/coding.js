const express = require('express');
const router = express.Router();
const { auth: authenticateToken } = require('../middleware/auth');
const logger = require('../middleware/logger');
const CodingQuestion = require('../models/CodingQuestion');
const CodingTestCase = require('../models/CodingTestCase');
const TestCodingSection = require('../models/TestCodingSection');
const CodingSubmission = require('../models/CodingSubmission');
const PracticeCodingProgress = require('../models/PracticeCodingProgress');
const ivm = require('isolated-vm');

router.get('/questions', authenticateToken, async (req, res) => {
  try {
    const questions = await CodingQuestion.find()
      .select('_id title difficulty tags created_at')
      .sort({ created_at: -1 })
      .lean();

    const questionsWithCounts = await Promise.all(
      questions.map(async (q) => {
        const testCasesCount = await CodingTestCase.countDocuments({ question_id: q._id });
        return {
          id: q._id,
          title: q.title,
          difficulty: q.difficulty,
          tags: q.tags,
          created_at: q.created_at,
          test_cases_count: testCasesCount
        };
      })
    );

    res.json(questionsWithCounts);
  } catch (error) {
    logger.errorLog(error, { context: 'Error fetching coding questions' });
    res.status(500).json({ error: 'Failed to fetch coding questions' });
  }
});

router.get('/questions/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const question = await CodingQuestion.findById(id).lean();
    if (!question) {
      return res.status(404).json({ error: 'Question not found' });
    }

    const testCases = await CodingTestCase.find({ question_id: id })
      .sort({ is_sample: -1 })
      .lean();

    res.json({
      data: {
        id: question._id,
        ...question,
        testCases: testCases.map(tc => ({
          id: tc._id,
          ...tc
        }))
      }
    });
  } catch (error) {
    logger.errorLog(error, { context: 'Error fetching coding question' });
    res.status(500).json({ error: 'Failed to fetch coding question' });
  }
});

router.post('/questions', authenticateToken, async (req, res) => {
  try {
    const { testCases, ...questionData } = req.body;

    const question = new CodingQuestion({
      ...questionData,
      created_by: req.user.id
    });

    await question.save();

    if (testCases && testCases.length > 0) {
      const testCasesData = testCases.map(tc => ({
        question_id: question._id,
        input: tc.input,
        expected_output: tc.expected_output,
        is_sample: tc.is_sample,
        weight: tc.weight
      }));

      await CodingTestCase.insertMany(testCasesData);
    }

    res.json({
      id: question._id,
      ...question.toObject()
    });
  } catch (error) {
    logger.errorLog(error, { context: 'Error creating coding question' });
    res.status(500).json({ error: 'Failed to create coding question' });
  }
});

router.put('/questions/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { testCases, ...questionData } = req.body;

    const question = await CodingQuestion.findByIdAndUpdate(
      id,
      {
        ...questionData,
        updated_at: new Date()
      },
      { new: true }
    );

    if (!question) {
      return res.status(404).json({ error: 'Question not found' });
    }

    if (testCases) {
      await CodingTestCase.deleteMany({ question_id: id });

      if (testCases.length > 0) {
        const testCasesData = testCases.map(tc => ({
          question_id: id,
          input: tc.input,
          expected_output: tc.expected_output,
          is_sample: tc.is_sample,
          weight: tc.weight
        }));

        await CodingTestCase.insertMany(testCasesData);
      }
    }

    res.json({
      id: question._id,
      ...question.toObject()
    });
  } catch (error) {
    logger.errorLog(error, { context: 'Error updating coding question' });
    res.status(500).json({ error: 'Failed to update coding question' });
  }
});

router.delete('/questions/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const question = await CodingQuestion.findByIdAndDelete(id);
    if (!question) {
      return res.status(404).json({ error: 'Question not found' });
    }

    await CodingTestCase.deleteMany({ question_id: id });
    await TestCodingSection.deleteMany({ question_id: id });
    await CodingSubmission.deleteMany({ question_id: id });
    await PracticeCodingProgress.deleteMany({ question_id: id });

    res.json({ message: 'Question deleted successfully' });
  } catch (error) {
    logger.errorLog(error, { context: 'Error deleting coding question' });
    res.status(500).json({ error: 'Failed to delete coding question' });
  }
});

router.post('/run', authenticateToken, async (req, res) => {
  try {
    const { questionId, code, language } = req.body;

    const testCases = await CodingTestCase.find({
      question_id: questionId,
      is_sample: true
    }).lean();

    if (testCases.length === 0) {
      return res.status(400).json({ error: 'No sample test cases found' });
    }

    const results = await executeCode(code, language, testCases);

    res.json({
      output: results.output,
      testResults: results.testResults
    });
  } catch (error) {
    logger.errorLog(error, { context: 'Error running code' });
    res.status(500).json({ error: error.message || 'Failed to run code' });
  }
});

router.post('/submit', authenticateToken, async (req, res) => {
  try {
    const { questionId, testAttemptId, code, language, isPractice } = req.body;

    const testCases = await CodingTestCase.find({ question_id: questionId }).lean();

    if (testCases.length === 0) {
      return res.status(400).json({ error: 'No test cases found for this question' });
    }

    const results = await executeCode(code, language, testCases);

    const testCasesPassed = results.testResults.filter(r => r.passed).length;
    const totalTestCases = testCases.length;
    const totalWeight = testCases.reduce((sum, tc) => sum + tc.weight, 0);
    const earnedWeight = results.testResults
      .filter(r => r.passed)
      .reduce((sum, r) => {
        const tc = testCases[r.test_case_number - 1];
        return sum + (tc?.weight || 0);
      }, 0);
    // Compute score. If totalWeight is zero (weights missing or zero),
    // fall back to simple pass-rate based scoring to avoid 0 points when tests pass.
    let score;
    if (totalWeight > 0) {
      score = Math.round((earnedWeight / totalWeight) * 100);
    } else {
      // fallback: use proportion of passed test cases
      score = totalTestCases > 0 ? Math.round((testCasesPassed / totalTestCases) * 100) : 0;
    }

    // Log scoring details for debugging
    try {
      logger.info('Scoring details', {
        questionId,
        testCasesCount: totalTestCases,
        testCasesPassed,
        totalWeight,
        earnedWeight,
        score
      });
    } catch (e) {
      // swallow logging errors - do not affect submission
      console.warn('Failed to log scoring details', e && e.message);
    }

    let status = 'wrong_answer';
    if (testCasesPassed === totalTestCases) {
      status = 'accepted';
    } else if (results.hasRuntimeError) {
      status = 'runtime_error';
    } else if (results.hasTimeLimit) {
      status = 'time_limit_exceeded';
    }

    const submission = new CodingSubmission({
      student_id: req.user.id,
      question_id: questionId,
      test_attempt_id: testAttemptId || null,
      language,
      code,
      status,
      test_cases_passed: testCasesPassed,
      total_test_cases: totalTestCases,
      score,
      execution_time: results.avgExecutionTime,
      test_results: results.testResults
    });

    await submission.save();

    if (isPractice) {
      const progressStatus = status === 'accepted' ? 'solved' : 'attempted';

      const existing = await PracticeCodingProgress.findOne({
        student_id: req.user.id,
        question_id: questionId
      });

      if (existing) {
        const updates = {
          status: status === 'accepted' ? 'solved' : existing.status,
          best_score: Math.max(score, existing.best_score || 0),
          attempts: (existing.attempts || 0) + 1,
          last_attempted_at: new Date()
        };

        if (status === 'accepted' && existing.status !== 'solved') {
          updates.solved_at = new Date();
        }

        await PracticeCodingProgress.findByIdAndUpdate(existing._id, updates);
      } else {
        const progress = new PracticeCodingProgress({
          student_id: req.user.id,
          question_id: questionId,
          status: progressStatus,
          best_score: score,
          attempts: 1,
          last_attempted_at: new Date(),
          solved_at: status === 'accepted' ? new Date() : null
        });

        await progress.save();
      }
    }

    res.json({
      submissionId: submission._id,
      status,
      testCasesPassed,
      totalTestCases,
      score,
      testResults: results.testResults.map(r => ({
        ...r,
        input: testCases[r.test_case_number - 1]?.is_sample ? r.input : '[Hidden]',
        expected_output: testCases[r.test_case_number - 1]?.is_sample ? r.expected_output : '[Hidden]'
      }))
    });
  } catch (error) {
    logger.errorLog(error, { context: 'Error submitting code' });
    res.status(500).json({ error: error.message || 'Failed to submit code' });
  }
});

router.get('/practice/questions', authenticateToken, async (req, res) => {
  try {
    const questions = await CodingQuestion.find()
      .select('_id title difficulty tags')
      .lean();

    const progress = await PracticeCodingProgress.find({
      student_id: req.user.id
    }).lean();

    const progressMap = new Map(progress.map(p => [p.question_id.toString(), p]));

    const questionsWithProgress = questions.map(q => {
      const prog = progressMap.get(q._id.toString());
      return {
        id: q._id,
        title: q.title,
        difficulty: q.difficulty,
        tags: q.tags,
        status: prog?.status || 'not_attempted',
        best_score: prog?.best_score,
        attempts: prog?.attempts
      };
    });

    const stats = {
      total: questions.length,
      solved: progress.filter(p => p.status === 'solved').length,
      attempted: progress.filter(p => p.status === 'attempted').length,
      easy: questions.filter(q => q.difficulty === 'easy').length,
      medium: questions.filter(q => q.difficulty === 'medium').length,
      hard: questions.filter(q => q.difficulty === 'hard').length
    };

    res.json({
      questions: questionsWithProgress,
      stats
    });
  } catch (error) {
    logger.errorLog(error, { context: 'Error fetching practice questions' });
    res.status(500).json({ error: 'Failed to fetch practice questions' });
  }
});

router.get('/submissions/:questionId', authenticateToken, async (req, res) => {
  try {
    const { questionId } = req.params;

    const submissions = await CodingSubmission.find({
      student_id: req.user.id,
      question_id: questionId
    })
      .sort({ submitted_at: -1 })
      .limit(10)
      .lean();

    res.json(submissions.map(s => ({
      id: s._id,
      ...s
    })));
  } catch (error) {
    logger.errorLog(error, { context: 'Error fetching submissions' });
    res.status(500).json({ error: 'Failed to fetch submissions' });
  }
});

async function executeCode(code, language, testCases) {
  const results = {
    output: '',
    testResults: [],
    avgExecutionTime: 0,
    hasRuntimeError: false,
    hasTimeLimit: false
  };

  try {
    for (let i = 0; i < testCases.length; i++) {
      const testCase = testCases[i];
      const startTime = Date.now();

      try {
        const output = await runCodeInSandbox(code, language, testCase.input);
        const executionTime = Date.now() - startTime;

        const passed = output.trim() === testCase.expected_output.trim();

        results.testResults.push({
          test_case_number: i + 1,
          passed,
          input: testCase.input,
          expected_output: testCase.expected_output,
          actual_output: output,
          execution_time: executionTime
        });

        results.avgExecutionTime += executionTime;
      } catch (error) {
        results.hasRuntimeError = true;
        results.testResults.push({
          test_case_number: i + 1,
          passed: false,
          input: testCase.input,
          expected_output: testCase.expected_output,
          error: error.message
        });
      }
    }

    results.avgExecutionTime = Math.round(results.avgExecutionTime / testCases.length);

    if (results.testResults.length > 0 && results.testResults[0].passed) {
      results.output = 'All sample test cases passed!';
    } else {
      results.output = 'Some test cases failed. Check the results below.';
    }
  } catch (error) {
    results.output = `Error: ${error.message}`;
    results.hasRuntimeError = true;
  }

  return results;
}

async function runCodeInSandbox(code, language, input) {
  return new Promise(async (resolve, reject) => {
    const timeout = 5000;

    try {
      if (language === 'javascript') {
        const isolate = new ivm.Isolate({ memoryLimit: 128 });
        const context = await isolate.createContext();

        const jail = context.global;
        await jail.set('global', jail.derefInto());

        const outputLogs = [];
        await jail.set('_consoleLog', new ivm.Reference(function(...args) {
          outputLogs.push(args.map(a => String(a)).join(' '));
        }));

        const inputLines = input.split('\n');
        await jail.set('_inputLines', JSON.stringify(inputLines));
        await jail.set('_inputIndex', 0);

        const wrappedCode = `
          let _inputLines = JSON.parse(_inputLines);
          let _inputIndex = 0;

          const console = {
            log: (...args) => _consoleLog.applySync(undefined, args)
          };

          const readline = () => {
            if (_inputIndex < _inputLines.length) {
              return _inputLines[_inputIndex++];
            }
            return '';
          };

          ${code}

          // Capture console output
          '';
        `;

        try {
          const script = await isolate.compileScript(wrappedCode);
          await script.run(context, { timeout });

          const output = outputLogs.join('\n');
          isolate.dispose();
          resolve(output);
        } catch (error) {
          isolate.dispose();
          reject(new Error(`Runtime Error: ${error.message}`));
        }
      } else if (language === 'python') {
        // For Python execution, we'll use child_process to run Python
        const { execSync } = require('child_process');
        const fs = require('fs');
        const path = require('path');
        const os = require('os');

        try {
          // Create a temporary file for the Python script
          const tempDir = os.tmpdir();
          const tempFile = path.join(tempDir, `temp_${Date.now()}.py`);

          // Wrap the user code to provide input automatically
          const wrappedCode = `
import sys
from io import StringIO

# Prepare input
input_data = ${JSON.stringify(input)}
sys.stdin = StringIO(input_data)

# User's code
${code}
`;

          // Write the code to a temporary file
          fs.writeFileSync(tempFile, wrappedCode, 'utf8');

          try {
            // Execute Python script
            const result = execSync(`python "${tempFile}"`, {
              encoding: 'utf8',
              timeout: timeout,
              maxBuffer: 10 * 1024 * 1024,
              stdio: ['pipe', 'pipe', 'pipe'],
              shell: true,
              windowsHide: true
            });

            // Clean up - ensure file is deleted even if there's an error
            try {
              fs.unlinkSync(tempFile);
            } catch (cleanupError) {
              console.warn('Warning: Failed to delete temp file:', tempFile);
            }
            
            resolve(result.trim());
          } catch (execError) {
            // Clean up on error
            try {
              fs.unlinkSync(tempFile);
            } catch (cleanupError) {
              console.warn('Warning: Failed to delete temp file after error:', tempFile);
            }
            
            // Extract the actual error message from stderr or stdout
            let errorMsg = execError.message;
            if (execError.stderr && typeof execError.stderr === 'string' && execError.stderr.trim()) {
              errorMsg = execError.stderr.trim();
            } else if (execError.stdout && typeof execError.stdout === 'string' && execError.stdout.trim()) {
              errorMsg = execError.stdout.trim();
            }
            
            reject(new Error(`Python Runtime Error: ${errorMsg}`));
          }
        } catch (error) {
          reject(new Error(`Python Error: ${error.message}`));
        }
      } else if (language === 'java') {
        resolve(`Java execution requires JDK runtime. Please use JavaScript for now.`);
      } else if (language === 'cpp') {
        resolve(`C++ execution requires C++ compiler. Please use JavaScript for now.`);
      } else {
        reject(new Error(`Language ${language} is not supported`));
      }
    } catch (error) {
      reject(new Error(`Execution Error: ${error.message}`));
    }
  });
}

module.exports = router;
