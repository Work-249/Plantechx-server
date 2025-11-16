// Detailed debugging script to test the submit endpoint
const http = require('http');

const submissionData = {
  questionId: '507f1f77bcf86cd799439011', // Sample MongoDB ID
  testAttemptId: null,
  code: `S = input().strip()
vowels = 'aeiouAEIOU'
count = 0
for char in S:
    if char in vowels:
        count += 1
print(count)`,
  language: 'python',
  isPractice: true
};

// Note: This is a fake JWT token - you need a real one
const fakeToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjUwN2YxZjc3YmNmODZjZDc5OTQzOTAxMSIsImlhdCI6MTczMDAzNjEwMX0.test';

const options = {
  hostname: 'localhost',
  port: 5000,
  path: '/api/coding/submit',
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${fakeToken}`
  }
};

console.log('='.repeat(60));
console.log('Testing Code Submission');
console.log('='.repeat(60));
console.log('\nRequest Details:');
console.log('- URL:', `${options.method} http://localhost:${options.port}${options.path}`);
console.log('- Headers:', JSON.stringify(options.headers, null, 2));
console.log('- Body:', JSON.stringify(submissionData, null, 2));
console.log('\n' + '='.repeat(60));
console.log('Response:');
console.log('='.repeat(60) + '\n');

const req = http.request(options, (res) => {
  let responseData = '';

  res.on('data', (chunk) => {
    responseData += chunk;
  });

  res.on('end', () => {
    console.log('Status Code:', res.statusCode);
    console.log('Status Message:', res.statusMessage);
    console.log('\nResponse Headers:');
    console.log(JSON.stringify(res.headers, null, 2));
    console.log('\nResponse Body:');
    try {
      const parsed = JSON.parse(responseData);
      console.log(JSON.stringify(parsed, null, 2));
    } catch (e) {
      console.log(responseData);
    }
    console.log('\n' + '='.repeat(60));
    if (res.statusCode === 200) {
      console.log('✅ SUCCESS');
    } else {
      console.log('❌ ERROR');
    }
    console.log('='.repeat(60));
  });
});

req.on('error', (error) => {
  console.error('❌ Request Error:', error.message);
  if (error.code === 'ECONNREFUSED') {
    console.error('\n⚠️  Server is not running on port 5000');
    console.error('   Start server with: npm start (in server directory)');
  }
});

// Send the data
req.write(JSON.stringify(submissionData));
req.end();
