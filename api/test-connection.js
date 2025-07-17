const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });
const mongoose = require('mongoose');

console.log('=== MongoDB Connection Test ===');
console.log('NODE_ENV:', process.env.NODE_ENV);
console.log('MONGODB_URI exists:', !!process.env.MONGODB_URI);
console.log('MONGODB_URI length:', process.env.MONGODB_URI?.length);

// Mask the URI for security but show structure
if (process.env.MONGODB_URI) {
    const uri = process.env.MONGODB_URI;
    const maskedUri = uri.replace(/:([^:@]+)@/, ':***@');
    console.log('MONGODB_URI structure:', maskedUri);
}

async function testConnection() {
    try {
        console.log('\n--- Testing MongoDB Connection ---');
        
        const conn = await mongoose.connect(process.env.MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            serverSelectionTimeoutMS: 10000,
            socketTimeoutMS: 45000,
            connectTimeoutMS: 10000,
        });
        
        console.log('✅ Connection successful!');
        console.log('Host:', conn.connection.host);
        console.log('Port:', conn.connection.port);
        console.log('Database:', conn.connection.name);
        
        // Test a simple operation
        const admin = mongoose.connection.db.admin();
        const ping = await admin.ping();
        console.log('✅ Ping successful:', ping);
        
        // List databases
        const dbs = await admin.listDatabases();
        console.log('Available databases:', dbs.databases.map(db => db.name));
        
        await mongoose.disconnect();
        console.log('✅ Disconnected successfully');
        
    } catch (error) {
        console.error('❌ Connection failed:');
        console.error('Error name:', error.name);
        console.error('Error message:', error.message);
        console.error('Error code:', error.code);
        console.error('Error codeName:', error.codeName);
        
        if (error.reason) {
            console.error('Error reason:', error.reason);
        }
        
        process.exit(1);
    }
}

testConnection();