const { execSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

// Simulate the Python code that might have an error
const testCases = [
  {
    input: 'OpenAI ChatGPT',
    expected_output: '5'
  }
];

const code = `S = input().strip()
vowels = 'aeiouAEIOU'
count = 0
for char in S:
    if char in vowels:
        count += 1
print(count)`;

console.log('Testing Python Code Execution');
console.log('=====================================');
console.log('Code:');
console.log(code);
console.log('=====================================');
console.log('Test Cases:');
testCases.forEach((tc, idx) => {
  console.log(`\nTest Case ${idx + 1}:`);
  console.log('  Input:', tc.input);
  console.log('  Expected:', tc.expected_output);
});
console.log('\n=====================================');

testCases.forEach((testCase, idx) => {
  try {
    const tempDir = os.tmpdir();
    const tempFile = path.join(tempDir, `temp_${Date.now()}_${idx}.py`);

    const wrappedCode = `import sys
from io import StringIO

# Prepare input
input_data = ${JSON.stringify(testCase.input)}
sys.stdin = StringIO(input_data)

# User's code
${code}
`;

    fs.writeFileSync(tempFile, wrappedCode, 'utf8');

    try {
      const result = execSync(`python "${tempFile}"`, {
        encoding: 'utf8',
        timeout: 5000,
        maxBuffer: 10 * 1024 * 1024,
        stdio: ['pipe', 'pipe', 'pipe']
      });

      fs.unlinkSync(tempFile);
      
      const output = result.trim();
      const passed = output === testCase.expected_output;
      
      console.log(`\nTest Case ${idx + 1} Result:`);
      console.log('  Actual Output:', output);
      console.log('  Expected Output:', testCase.expected_output);
      console.log('  Status:', passed ? '✓ PASSED' : '✗ FAILED');
      
    } catch (execError) {
      try { fs.unlinkSync(tempFile); } catch (e) {}
      
      console.log(`\nTest Case ${idx + 1} Error:`);
      console.log('  Error:', execError.message);
      if (execError.stderr) {
        console.log('  Stderr:', execError.stderr.toString());
      }
      if (execError.stdout) {
        console.log('  Stdout:', execError.stdout.toString());
      }
    }
  } catch (error) {
    console.log(`\nTest Case ${idx + 1} Setup Error:`);
    console.log('  Error:', error.message);
  }
});
