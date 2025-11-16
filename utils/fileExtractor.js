const csv = require('csv-parser');
const { Readable } = require('stream');

class FileExtractor {
  static async extractFromJSON(buffer) {
    try {
      const fileContent = buffer.toString('utf-8');
      const data = JSON.parse(fileContent);

      if (!Array.isArray(data)) {
        throw new Error('JSON file must contain an array of questions');
      }

      const questions = data.map((item, index) => {
        // Determine if this is an image-based question
        const isImageQuestion = item.questionType === 'image' || (!item.questionText && (item.optionImages || item.optionAImage || item.optionBImage || item.optionCImage || item.optionDImage));

        // Support optional image fields in the JSON. Accept multiple common key names.
        const questionImageUrl = item.questionImageUrl || item.questionImage || item.image || item.question_image || null;

        // Option images may be provided as an object `optionImages` or as individual keys.
        const optionImages = {
          A: null,
          B: null,
          C: null,
          D: null
        };

        if (item.optionImages && typeof item.optionImages === 'object') {
          optionImages.A = item.optionImages.A || item.optionImages.a || optionImages.A;
          optionImages.B = item.optionImages.B || item.optionImages.b || optionImages.B;
          optionImages.C = item.optionImages.C || item.optionImages.c || optionImages.C;
          optionImages.D = item.optionImages.D || item.optionImages.d || optionImages.D;
        }

        // Individual option image keys
        optionImages.A = optionImages.A || item.optionAImage || item.optionA_image || item.A_image || item.AImage || null;
        optionImages.B = optionImages.B || item.optionBImage || item.optionB_image || item.B_image || item.BImage || null;
        optionImages.C = optionImages.C || item.optionCImage || item.optionC_image || item.C_image || item.CImage || null;
        optionImages.D = optionImages.D || item.optionDImage || item.optionD_image || item.D_image || item.DImage || null;

        // If it's an image question, allow empty textual options but require option images
        if (isImageQuestion) {
          // Ensure correctAnswer exists and is valid
          if (!item.correctAnswer || !['A', 'B', 'C', 'D'].includes(item.correctAnswer)) {
            throw new Error(`Invalid correct answer at index ${index}: ${item.correctAnswer}`);
          }

          // Ensure optionImages are provided (at least for the keys)
          if (!optionImages.A && !optionImages.B && !optionImages.C && !optionImages.D) {
            throw new Error(`Image question at index ${index} must provide optionImages for A, B, C, D`);
          }

          return {
            questionText: item.questionText || '',
            options: {
              A: (item.options && item.options.A) || '',
              B: (item.options && item.options.B) || '',
              C: (item.options && item.options.C) || '',
              D: (item.options && item.options.D) || ''
            },
            correctAnswer: item.correctAnswer,
            questionImageUrl: questionImageUrl || undefined,
            optionImages: optionImages
          };
        }

        // Basic validation for text-based MCQ
        if (!item.questionText || !item.options || !item.correctAnswer) {
          throw new Error(`Invalid question format at index ${index}`);
        }

        const options = item.options;
        if (!options.A || !options.B || !options.C || !options.D) {
          throw new Error(`Question at index ${index} must have options A, B, C, and D`);
        }

        if (!['A', 'B', 'C', 'D'].includes(item.correctAnswer)) {
          throw new Error(`Invalid correct answer at index ${index}: ${item.correctAnswer}`);
        }

        return {
          questionText: item.questionText,
          options: {
            A: options.A,
            B: options.B,
            C: options.C,
            D: options.D
          },
          correctAnswer: item.correctAnswer,
          // include optional image fields so frontend can display them
          questionImageUrl: questionImageUrl || undefined,
          optionImages: (optionImages.A || optionImages.B || optionImages.C || optionImages.D) ? optionImages : undefined
        };
      });

      return questions;
    } catch (error) {
      throw error;
    }
  }

  static async extractFromCSV(buffer) {
    try {
      const questions = [];

      await new Promise((resolve, reject) => {
        const stream = Readable.from(buffer);
        stream
          .pipe(csv())
          .on('data', (row) => {
            try {
              const question = {
                questionText: row.question || row.questionText || row.Question,
                options: {
                  A: row.optionA || row.option_a || row.A || row['Option A'],
                  B: row.optionB || row.option_b || row.B || row['Option B'],
                  C: row.optionC || row.option_c || row.C || row['Option C'],
                  D: row.optionD || row.option_d || row.D || row['Option D']
                },
                correctAnswer: (row.correctAnswer || row.correct_answer || row.answer || row.Answer).toUpperCase()
              };

              if (!question.questionText ||
                  !question.options.A || !question.options.B ||
                  !question.options.C || !question.options.D ||
                  !['A', 'B', 'C', 'D'].includes(question.correctAnswer)) {
                console.warn('Skipping invalid row:', row);
                return;
              }

              questions.push(question);
            } catch (error) {
              console.warn('Error parsing row:', row, error);
            }
          })
          .on('end', () => {
            resolve();
          })
          .on('error', (error) => {
            reject(error);
          });
      });

      if (questions.length === 0) {
        throw new Error('No valid questions found in CSV file. Please check the format.');
      }

      return questions;
    } catch (error) {
      throw error;
    }
  }
}

module.exports = FileExtractor;
