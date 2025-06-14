// Quick test to verify the new SDK import works
const { GoogleGenAI } = require('@google/genai');

console.log('✅ New SDK import successful');
console.log('GoogleGenAI class:', typeof GoogleGenAI);

// Test creating a client (without API key, just to check constructor)
try {
  const client = new GoogleGenAI({ apiKey: 'test' });
  console.log('✅ Client creation successful');
  console.log('Client has models property:', 'models' in client);
} catch (error) {
  console.log('❌ Client creation failed:', error.message);
}
