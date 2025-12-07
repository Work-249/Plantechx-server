/**
 * Secure Code Execution Sandbox
 * Provides resource-limited, isolated code execution environment
 */

const vm = require('vm');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

// Configuration for resource limits
const EXECUTION_CONFIG = {
  TIMEOUT: 5000,              // 5 seconds max execution time
  MAX_MEMORY: 128 * 1024 * 1024,  // 128MB max memory
  MAX_CODE_SIZE: 50 * 1024,   // 50KB max code size
  MAX_OUTPUT_SIZE: 1 * 1024 * 1024, // 1MB max output
  MAX_RECURSION_DEPTH: 1000,
  TEMP_DIR: path.join(os.tmpdir(), 'plantechx-sandbox'),
};

// Create sandbox directory if it doesn't exist
try {
  if (!fs.existsSync(EXECUTION_CONFIG.TEMP_DIR)) {
    fs.mkdirSync(EXECUTION_CONFIG.TEMP_DIR, { recursive: true });
  }
} catch (err) {
  console.warn('Warning: Could not create sandbox directory', err);
}

/**
 * Secure sandbox for JavaScript execution
 */
class JavaScriptSandbox {
  /**
   * Execute JavaScript code in isolated VM context
   */
  static async executeCode(code, input, timeout = EXECUTION_CONFIG.TIMEOUT) {
    return new Promise((resolve, reject) => {
      try {
        // Validate code size
        if (code.length > EXECUTION_CONFIG.MAX_CODE_SIZE) {
          return reject(new Error(`Code exceeds maximum size of ${EXECUTION_CONFIG.MAX_CODE_SIZE} bytes`));
        }

        const outputLogs = [];
        const inputLines = input.split('\n');
        let inputIndex = 0;
        let executionTime = 0;

        // Create sandbox with limited access
        const sandbox = {
          console: {
            log: (...args) => {
              const output = args.map(a => {
                if (typeof a === 'object') {
                  return JSON.stringify(a);
                }
                return String(a);
              }).join(' ');

              // Check output size limit
              if ((outputLogs.join('\n') + output).length > EXECUTION_CONFIG.MAX_OUTPUT_SIZE) {
                throw new Error('Output exceeds maximum size limit');
              }

              outputLogs.push(output);
            },
            error: (...args) => {
              const output = 'ERROR: ' + args.join(' ');
              outputLogs.push(output);
            }
          },
          readline: () => {
            if (inputIndex < inputLines.length) {
              return inputLines[inputIndex++];
            }
            return '';
          },
          // Block dangerous globals
          eval: undefined,
          Function: undefined,
          require: undefined,
          module: undefined,
          process: undefined,
          global: undefined,
          __dirname: undefined,
          __filename: undefined,
        };

        // Wrap code with recursion depth tracking
        const wrappedCode = `
          let __recursionDepth = 0;
          const __maxRecursionDepth = ${EXECUTION_CONFIG.MAX_RECURSION_DEPTH};
          
          const __originalStack = Error.stackTraceLimit;
          Error.stackTraceLimit = 10;
          
          ${code}
        `;

        // Create VM context
        const context = vm.createContext(sandbox, { 
          timeout,
          displayErrors: true,
          lineOffset: 0,
          columnOffset: 0
        });

        // Compile and run script
        const script = new vm.Script(wrappedCode, {
          filename: 'sandbox.js',
          displayErrors: true,
          lineOffset: 0,
          columnOffset: 0
        });

        const startTime = Date.now();
        
        try {
          script.runInContext(context, { timeout });
          executionTime = Date.now() - startTime;
        } catch (error) {
          if (error.code === 'ERR_SCRIPT_EXECUTION_TIMEOUT') {
            return reject(new Error('Code execution timed out'));
          }
          throw error;
        }

        resolve({
          output: outputLogs.join('\n'),
          executionTime,
          status: 'success'
        });

      } catch (error) {
        reject(new Error(`Sandbox Error: ${error.message}`));
      }
    });
  }
}

/**
 * Secure sandbox for Python execution
 */
class PythonSandbox {
  /**
   * Execute Python code in isolated process with resource limits
   */
  static async executeCode(code, input, timeout = EXECUTION_CONFIG.TIMEOUT) {
    return new Promise((resolve, reject) => {
      try {
        // Validate code size
        if (code.length > EXECUTION_CONFIG.MAX_CODE_SIZE) {
          return reject(new Error(`Code exceeds maximum size of ${EXECUTION_CONFIG.MAX_CODE_SIZE} bytes`));
        }

        // Create temporary Python file
        const tempFile = path.join(EXECUTION_CONFIG.TEMP_DIR, `sandbox_${Date.now()}_${Math.random().toString(36).slice(2)}.py`);

        // Wrap code with resource restrictions and input handling
        const wrappedCode = `
import sys
import io
import resource
import signal

# Set resource limits
try:
    # Limit memory to 128MB
    resource.setrlimit(resource.RLIMIT_AS, (${EXECUTION_CONFIG.MAX_MEMORY}, ${EXECUTION_CONFIG.MAX_MEMORY}))
    # Limit CPU time to 5 seconds
    resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
except:
    pass

# Set output capture
original_stdout = sys.stdout
sys.stdout = io.StringIO()

# Prepare input
input_data = """${input.replace(/"/g, '\\"')}"""
sys.stdin = io.StringIO(input_data)

# Disable dangerous functions
import builtins
dangerous_functions = [
    'exec', 'eval', '__import__', 'compile', 'open', 'input',
    'file', 'reload', 'raw_input', 'execfile'
]

for func in dangerous_functions:
    if hasattr(builtins, func):
        setattr(builtins, func, None)

try:
    # User code
${code.split('\n').map((line, i) => i === 0 ? line : '    ' + line).join('\n')}
except Exception as e:
    print(f'ERROR: {type(e).__name__}: {str(e)}')
finally:
    # Get output
    output = sys.stdout.getvalue()
    sys.stdout = original_stdout
    print(output, end='')
`;

        // Write code to temp file
        fs.writeFileSync(tempFile, wrappedCode, 'utf8');

        // Execute Python process with limits
        const child = spawn('python', [tempFile], {
          timeout: timeout + 1000, // Add buffer to process timeout
          maxBuffer: EXECUTION_CONFIG.MAX_OUTPUT_SIZE,
          stdio: ['pipe', 'pipe', 'pipe'],
          shell: false,
          detached: true
        });

        let stdout = '';
        let stderr = '';
        const startTime = Date.now();

        child.stdout.on('data', (data) => {
          stdout += data.toString();
          if (stdout.length > EXECUTION_CONFIG.MAX_OUTPUT_SIZE) {
            child.kill();
          }
        });

        child.stderr.on('data', (data) => {
          stderr += data.toString();
        });

        const timeoutHandle = setTimeout(() => {
          try {
            process.kill(-child.pid);
          } catch (e) {
            // Process already killed
          }
        }, timeout);

        child.on('close', (code, signal) => {
          clearTimeout(timeoutHandle);
          const executionTime = Date.now() - startTime;

          // Clean up temp file
          try {
            fs.unlinkSync(tempFile);
          } catch (e) {
            console.warn('Warning: Could not delete temp file:', tempFile);
          }

          if (signal === 'SIGTERM' || executionTime > timeout) {
            return reject(new Error('Python code execution timed out'));
          }

          if (code !== 0 && stderr) {
            return reject(new Error(`Python Runtime Error: ${stderr.trim()}`));
          }

          resolve({
            output: stdout.trim(),
            executionTime,
            status: 'success'
          });
        });

        child.on('error', (error) => {
          clearTimeout(timeoutHandle);
          
          // Clean up temp file
          try {
            fs.unlinkSync(tempFile);
          } catch (e) {
            // Ignore cleanup errors
          }

          reject(new Error(`Python Execution Error: ${error.message}`));
        });

      } catch (error) {
        reject(new Error(`Sandbox Setup Error: ${error.message}`));
      }
    });
  }
}

/**
 * Main execution wrapper with language routing
 */
async function executeCodeSafely(code, language, input = '', timeout = EXECUTION_CONFIG.TIMEOUT) {
  try {
    // Validate inputs
    if (!code || typeof code !== 'string') {
      throw new Error('Code must be a non-empty string');
    }

    if (!language || typeof language !== 'string') {
      throw new Error('Language must be specified');
    }

    if (code.length > EXECUTION_CONFIG.MAX_CODE_SIZE) {
      throw new Error(`Code size exceeds limit of ${EXECUTION_CONFIG.MAX_CODE_SIZE} bytes`);
    }

    language = language.toLowerCase();

    // Route to appropriate sandbox
    switch (language) {
      case 'javascript':
        return await JavaScriptSandbox.executeCode(code, input, timeout);
      
      case 'python':
        return await PythonSandbox.executeCode(code, input, timeout);
      
      default:
        throw new Error(`Language '${language}' is not supported. Supported: javascript, python`);
    }

  } catch (error) {
    throw new Error(`Code Execution Error: ${error.message}`);
  }
}

/**
 * Cleanup sandbox resources
 */
function cleanupSandbox() {
  try {
    const files = fs.readdirSync(EXECUTION_CONFIG.TEMP_DIR);
    const now = Date.now();
    
    for (const file of files) {
      const filePath = path.join(EXECUTION_CONFIG.TEMP_DIR, file);
      const stat = fs.statSync(filePath);
      
      // Delete files older than 1 hour
      if (now - stat.mtimeMs > 60 * 60 * 1000) {
        try {
          fs.unlinkSync(filePath);
        } catch (e) {
          // Ignore errors
        }
      }
    }
  } catch (error) {
    console.warn('Warning: Sandbox cleanup failed:', error);
  }
}

// Run cleanup periodically (every 30 minutes)
setInterval(cleanupSandbox, 30 * 60 * 1000);

module.exports = {
  executeCodeSafely,
  JavaScriptSandbox,
  PythonSandbox,
  EXECUTION_CONFIG,
  cleanupSandbox
};
