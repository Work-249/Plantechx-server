const pdf = require('pdf-parse');
const logger = require('../middleware/logger');

class PDFExtractor {
  static async extractMCQs(buffer) {
    try {
      const data = await pdf(buffer);

      let text = data.text.replace(/([ABCD]\))/g, '\n$1)');
      console.log('PDF text extracted, length:', text.length);
      console.log('First 500 characters:', text.substring(0, 500));

      // Parse MCQs from text using multiple parsing strategies
      let questions = [];

      // Try different parsing approaches
      questions = this.parseMCQText(text);

      if (questions.length === 0) {
        questions = this.parseAlternativeFormat(text);
      }

      if (questions.length === 0) {
        questions = this.parseSimpleFormat(text);
      }

      console.log('Extracted questions:', questions.length);

      return questions;
    } catch (error) {
      logger.errorLog(error, { context: 'PDF extraction error' });
      throw new Error('Failed to extract questions from PDF. Please ensure the PDF contains properly formatted MCQ questions with options A, B, C, D and correct answers.');
    }
  }

  static parseMCQText(text) {
    const questions = [];
    const lines = text.split('\n').map(line => line.trim()).filter(line => line.length > 0);

    let currentQuestion = null;
    let questionCounter = 0;
    let optionCount = 0;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Check if line starts with a number (question) - more flexible patterns
      const questionMatch = line.match(/^(\d+)[\.\)\s]+(.+)/);
      if (questionMatch) {
        // Save previous question if exists
        if (currentQuestion && this.isValidQuestion(currentQuestion)) {
          questions.push({
            questionText: currentQuestion.questionText,
            options: { ...currentQuestion.options },
            correctAnswer: currentQuestion.correctAnswer
          });
        }

        // Start new question
        questionCounter++;
        optionCount = 0;
        currentQuestion = {
          questionText: questionMatch[2].trim(),
          options: {},
          correctAnswer: null
        };
        continue;
      }

      // Check for options - more flexible patterns
      const optionMatch = line.match(/^[(\[]?([ABCD])[)\]\.:\s]*(.+)/i);
      if (optionMatch && currentQuestion) {
        const optionLetter = optionMatch[1].toUpperCase();
        const optionText = optionMatch[2].trim();
        if (optionText.length > 0 && !currentQuestion.options[optionLetter]) {
          currentQuestion.options[optionLetter] = optionText;
          optionCount++;
        }
        continue;
      }

      // Check for answer indication - more flexible patterns
      const answerMatch = line.match(/^(?:Answer|Ans|Correct|Solution)?[\s:]*[(\[]?([ABCD])[)\]]?/i);
      if (answerMatch && currentQuestion && optionCount === 4) {
        const answer = answerMatch[1].toUpperCase();
        if (!currentQuestion.correctAnswer) {
          currentQuestion.correctAnswer = answer;
        }
        continue;
      }

      // If we have a current question and this line doesn't match patterns,
      // it might be continuation of question text
      if (currentQuestion && optionCount === 0 && line.length > 10) {
        currentQuestion.questionText += ' ' + line;
      }
    }

    // Add the last question
    if (currentQuestion && this.isValidQuestion(currentQuestion)) {
      questions.push({
        questionText: currentQuestion.questionText,
        options: { ...currentQuestion.options },
        correctAnswer: currentQuestion.correctAnswer
      });
    }

    console.log('Parsed questions count:', questions.length);
    return questions;
  }

  static parseAlternativeFormat(text) {
    const questions = [];
    
    // Try to parse questions that might be in a different format
    // Look for patterns like "Q1:", "Question 1:", etc.
    const questionBlocks = text.split(/(?=Q\d+|Question\s+\d+)/i);
    
    for (const block of questionBlocks) {
      if (block.trim().length < 10) continue;
      
      const lines = block.split('\n').map(line => line.trim()).filter(line => line.length > 0);
      
      let questionText = '';
      const options = {};
      let correctAnswer = null;
      
      let foundOptions = false;
      
      for (const line of lines) {
        // Skip the question number line
        if (line.match(/^Q\d+|Question\s+\d+/i)) continue;
        
        // Check for options
        const optionMatch = line.match(/^([ABCD])[\.\)\s]+(.+)/i);
        if (optionMatch) {
          foundOptions = true;
          options[optionMatch[1].toUpperCase()] = optionMatch[2].trim();
          continue;
        }
        
        // Check for answer
        const answerMatch = line.match(/(?:Answer|Ans|Correct)[\s:]*([ABCD])/i);
        if (answerMatch) {
          correctAnswer = answerMatch[1].toUpperCase();
          continue;
        }
        
        // If no options found yet, this is part of question text
        if (!foundOptions && line.length > 5) {
          questionText += (questionText ? ' ' : '') + line;
        }
      }
      
      if (questionText && Object.keys(options).length === 4 && correctAnswer) {
        questions.push({
          questionText: questionText.trim(),
          options,
          correctAnswer
        });
      }
    }
    
    return questions;
  }

  static parseSimpleFormat(text) {
    const questions = [];
    
    // Very simple parsing - look for any text that has A), B), C), D) options
    const sections = text.split(/(?=\d+[\.\)]\s*[A-Z])/);
    
    for (const section of sections) {
      if (section.trim().length < 20) continue;
      
      const lines = section.split('\n').map(line => line.trim()).filter(line => line.length > 0);
      
      let questionText = '';
      const options = {};
      let correctAnswer = null;
      let foundFirstOption = false;
      
      for (const line of lines) {
        // Check for options
        const optionMatch = line.match(/^([ABCD])\)\s*(.+)/i);
        if (optionMatch) {
          foundFirstOption = true;
          options[optionMatch[1].toUpperCase()] = optionMatch[2].trim();
          continue;
        }
        
        // Check for answer
        if (line.match(/answer|correct/i)) {
          const answerMatch = line.match(/([ABCD])/i);
          if (answerMatch) {
            correctAnswer = answerMatch[1].toUpperCase();
            continue;
          }
        }
        
        // If no options found yet, this is question text
        if (!foundFirstOption && line.length > 5) {
          questionText += (questionText ? ' ' : '') + line;
        }
      }
      
      if (questionText && Object.keys(options).length >= 3 && correctAnswer) {
        // Fill missing options with placeholder text
        ['A', 'B', 'C', 'D'].forEach(letter => {
          if (!options[letter]) {
            options[letter] = `Option ${letter}`;
          }
        });
        
        questions.push({
          questionText: questionText.trim(),
          options,
          correctAnswer
        });
      }
    }
    
    return questions;
  }

  static isValidQuestion(question) {
    return question.questionText &&
           question.questionText.trim().length > 5 &&
           question.options.A &&
           question.options.B &&
           question.options.C &&
           question.options.D &&
           question.correctAnswer &&
           ['A', 'B', 'C', 'D'].includes(question.correctAnswer);
  }

  static generateSampleQuestions(count = 5, subject = 'General') {
    const sampleQuestions = {
      'Verbal': [
        {
          questionText: "Choose the word that is most similar in meaning to 'Abundant':",
          options: {
            A: "Scarce",
            B: "Plentiful", 
            C: "Limited",
            D: "Rare"
          },
          correctAnswer: "B"
        },
        {
          questionText: "Complete the sentence: 'The weather was so _____ that we decided to stay indoors.'",
          options: {
            A: "pleasant",
            B: "mild",
            C: "severe",
            D: "calm"
          },
          correctAnswer: "C"
        },
        {
          questionText: "Choose the correct synonym for 'Eloquent':",
          options: {
            A: "Silent",
            B: "Articulate",
            C: "Confused",
            D: "Hesitant"
          },
          correctAnswer: "B"
        },
        {
          questionText: "What is the antonym of 'Optimistic'?",
          options: {
            A: "Hopeful",
            B: "Positive",
            C: "Pessimistic",
            D: "Confident"
          },
          correctAnswer: "C"
        },
        {
          questionText: "Choose the word that best completes: 'Her _____ personality made her popular among colleagues.'",
          options: {
            A: "abrasive",
            B: "affable",
            C: "aloof",
            D: "aggressive"
          },
          correctAnswer: "B"
        }
      ],
      'Reasoning': [
        {
          questionText: "If all roses are flowers and some flowers are red, which conclusion is correct?",
          options: {
            A: "All roses are red",
            B: "Some roses may be red",
            C: "No roses are red", 
            D: "All red things are roses"
          },
          correctAnswer: "B"
        },
        {
          questionText: "What comes next in the sequence: 2, 6, 12, 20, ?",
          options: {
            A: "28",
            B: "30",
            C: "32",
            D: "24"
          },
          correctAnswer: "B"
        },
        {
          questionText: "If A = 1, B = 2, C = 3, what is the value of 'CAB'?",
          options: {
            A: "312",
            B: "321",
            C: "123",
            D: "132"
          },
          correctAnswer: "A"
        },
        {
          questionText: "In a certain code, 'BOOK' is written as 'CPPL'. How is 'PAGE' written?",
          options: {
            A: "QBHF",
            B: "QBGF",
            C: "QAHF",
            D: "PBHF"
          },
          correctAnswer: "A"
        },
        {
          questionText: "If Monday is the 1st day, what day is the 15th?",
          options: {
            A: "Sunday",
            B: "Monday",
            C: "Tuesday",
            D: "Wednesday"
          },
          correctAnswer: "B"
        }
      ],
      'Technical': [
        {
          questionText: "Which of the following is not a programming language?",
          options: {
            A: "Python",
            B: "Java",
            C: "HTML",
            D: "C++"
          },
          correctAnswer: "C"
        },
        {
          questionText: "What does CPU stand for?",
          options: {
            A: "Central Processing Unit",
            B: "Computer Processing Unit",
            C: "Central Program Unit",
            D: "Computer Program Unit"
          },
          correctAnswer: "A"
        },
        {
          questionText: "Which data structure follows LIFO (Last In First Out) principle?",
          options: {
            A: "Queue",
            B: "Stack",
            C: "Array",
            D: "Linked List"
          },
          correctAnswer: "B"
        },
        {
          questionText: "What is the time complexity of binary search?",
          options: {
            A: "O(n)",
            B: "O(n²)",
            C: "O(log n)",
            D: "O(1)"
          },
          correctAnswer: "C"
        },
        {
          questionText: "Which protocol is used for secure web communication?",
          options: {
            A: "HTTP",
            B: "FTP",
            C: "HTTPS",
            D: "SMTP"
          },
          correctAnswer: "C"
        }
      ],
      'Arithmetic': [
        {
          questionText: "What is 15% of 200?",
          options: {
            A: "25",
            B: "30",
            C: "35",
            D: "40"
          },
          correctAnswer: "B"
        },
        {
          questionText: "If a train travels 120 km in 2 hours, what is its speed?",
          options: {
            A: "50 km/h",
            B: "60 km/h",
            C: "70 km/h",
            D: "80 km/h"
          },
          correctAnswer: "B"
        },
        {
          questionText: "What is the value of 3² + 4² ?",
          options: {
            A: "25",
            B: "24",
            C: "23",
            D: "26"
          },
          correctAnswer: "A"
        },
        {
          questionText: "If x + 5 = 12, what is the value of x?",
          options: {
            A: "6",
            B: "7",
            C: "8",
            D: "9"
          },
          correctAnswer: "B"
        },
        {
          questionText: "What is 25% of 80?",
          options: {
            A: "15",
            B: "20",
            C: "25",
            D: "30"
          },
          correctAnswer: "B"
        }
      ],
      'Communication': [
        {
          questionText: "Which is the most effective way to start a presentation?",
          options: {
            A: "With a joke",
            B: "With statistics",
            C: "With a relevant question or story",
            D: "With an apology"
          },
          correctAnswer: "C"
        },
        {
          questionText: "Active listening involves:",
          options: {
            A: "Waiting for your turn to speak",
            B: "Giving full attention and providing feedback",
            C: "Thinking about your response",
            D: "Looking at your phone"
          },
          correctAnswer: "B"
        },
        {
          questionText: "What is the most important element of effective communication?",
          options: {
            A: "Speaking loudly",
            B: "Using complex vocabulary",
            C: "Clarity and understanding",
            D: "Speaking quickly"
          },
          correctAnswer: "C"
        },
        {
          questionText: "In written communication, what should you do first?",
          options: {
            A: "Start writing immediately",
            B: "Plan and organize your thoughts",
            C: "Use fancy words",
            D: "Write as much as possible"
          },
          correctAnswer: "B"
        },
        {
          questionText: "What is the key to effective teamwork?",
          options: {
            A: "Individual excellence",
            B: "Competition among members",
            C: "Clear communication and collaboration",
            D: "Working in isolation"
          },
          correctAnswer: "C"
        }
      ]
    };

    const questions = sampleQuestions[subject] || sampleQuestions['Technical'];
    return questions.slice(0, count);
  }
}

module.exports = PDFExtractor;