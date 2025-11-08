// Test JWT generation and validation
const jwt = require('jsonwebtoken');
const { appConfig } = require('./dist/lib/config.js');

console.log('🔑 JWT Secret Test');
console.log('JWT_SECRET from config:', appConfig.JWT_SECRET.substring(0, 20) + '...');

// Test token generation and validation
const testUserId = 5;
const token = jwt.sign({ userId: testUserId }, appConfig.JWT_SECRET, { expiresIn: '7d' });
console.log('Generated token:', token.substring(0, 50) + '...');

try {
  const decoded = jwt.verify(token, appConfig.JWT_SECRET);
  console.log('Token validation successful:', decoded);
} catch (error) {
  console.error('Token validation failed:', error.message);
}

// Test the specific token from curl
const curlToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjUsImlhdCI6MTc2MjYyMTMxMywiZXhwIjoxNzYzMjI2MTEzfQ.xzGBV9R1C3s1E13V8XANVEY0P81__691V1nzfCb_IHo';
console.log('\\nTesting curl token...');
try {
  const decoded = jwt.verify(curlToken, appConfig.JWT_SECRET);
  console.log('Curl token validation successful:', decoded);
} catch (error) {
  console.error('Curl token validation failed:', error.message);
}