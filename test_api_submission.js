// Test script to simulate a code submission
const http = require('http');

// Test data
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

// Prepare the request
const options = {
  hostname: 'localhost',
  port: 5000,
  path: '/api/coding/submit',
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer YOUR_JWT_TOKEN_HERE'
  }
};

console.log('Testing Code Submission Endpoint');
console.log('==================================');
console.log('Endpoint:', `${options.method} ${options.path}`);
console.log('Submission Data:', JSON.stringify(submissionData, null, 2));
console.log('==================================\n');

const req = http.request(options, (res) => {
  let responseData = '';

  res.on('data', (chunk) => {
    responseData += chunk;
  });

  res.on('end', () => {
    console.log('Status Code:', res.statusCode);
    console.log('Response Headers:', res.headers);
    console.log('\nResponse Body:');
    try {
      console.log(JSON.stringify(JSON.parse(responseData), null, 2));
    } catch (e) {
      console.log(responseData);
    }
  });
});

req.on('error', (error) => {
  console.error('Request Error:', error.message);
  if (error.code === 'ECONNREFUSED') {
    console.error('\n⚠️  Server is not running on port 5000');
    console.error('   Please start the server with: npm start or node server.js');
  }
});

// Send the data
req.write(JSON.stringify(submissionData));
req.end();
