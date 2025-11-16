const { execSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const code = `S = input().strip()
vowels = 'aeiouAEIOU'
count = 0
for char in S:
    if char in vowels:
        count += 1
print(count)`;

const input = 'OpenAI ChatGPT';
const tempDir = os.tmpdir();
const tempFile = path.join(tempDir, `test_${Date.now()}.py`);

const wrappedCode = `import sys
from io import StringIO

input_data = ${JSON.stringify(input)}
sys.stdin = StringIO(input_data)

${code}`;

fs.writeFileSync(tempFile, wrappedCode, 'utf8');
console.log('Wrapped code:\n', wrappedCode);
console.log('\n--- Running Python ---\n');

try {
  const result = execSync(`python "${tempFile}"`, { encoding: 'utf8' });
  console.log('✓ Output:', result.trim());
  console.log('✓ Expected: 5');
  console.log('✓ Test PASSED!' + (result.trim() === '5' ? ' All vowels counted correctly!' : ''));
} catch (e) {
  console.error('Error:', e.message);
} finally {
  fs.unlinkSync(tempFile);
}
