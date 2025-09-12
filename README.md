# PGP-Based Encrypted Messaging App

A full-stack web application for secure, end-to-end encrypted messaging using PGP encryption.

## Features

- **End-to-End Encryption**: Messages are encrypted with hybrid cryptography (RSA + AES)
- **PGP Key Management**: Automatic RSA key pair generation and management
- **Real-time Messaging**: WebSocket-based real-time message delivery
- **Secure Storage**: Private keys encrypted with user passphrase and stored locally
- **User-friendly Interface**: Clean, modern UI built with React and Tailwind CSS

## Tech Stack

### Frontend
- React.js with Next.js
- TypeScript
- Tailwind CSS
- OpenPGP.js for encryption
- Socket.IO client for real-time communication
- IndexedDB for local key storage

### Backend
- Node.js with Express
- MongoDB for data storage
- Socket.IO for real-time communication
- RESTful API design

## Getting Started

### Prerequisites
- Node.js (v18 or higher)
- MongoDB (local or cloud instance)
- npm or yarn

### Installation

1. Clone the repository:

``git clone https://github.com/turk-911/Secure-Chat.git``

``cd pgp-messaging-app``


2. Install dependencies for both client and server:

``npm install``

``cd server && npm install --legacy-peer-deps``

3. Set up environment variables (in server/.env):

``MONGODB_URI=add your database URL here``

``PORT=5001``

``CLIENT_URL=http://localhost:3000``


4. Start MongoDB (if running locally)

5. Run the application:

# Terminal 1: Start the server
``cd server && npm run dev``

# Terminal 2: Start the client
``npm run dev``


6. Open http://localhost:3000 in your browser

## How It Works

### Registration
1. User enters username and passphrase
2. RSA key pair is generated in the browser
3. Private key is encrypted with passphrase and stored locally
4. Public key is uploaded to the server

### Sending Messages
1. Generate random AES key
2. Encrypt message with AES key
3. Encrypt AES key with recipient's RSA public key
4. Send encrypted payload to server

### Receiving Messages
1. Fetch encrypted message from server
2. Decrypt AES key with user's RSA private key
3. Decrypt message with AES key
4. Display plaintext in UI

## API Endpoints

- `POST /api/register` - Register new user with public key
- `GET /api/publicKey/:username` - Get user's public key
- `POST /api/messages` - Send encrypted message
- `GET /api/messages/:username` - Get messages for user
- `GET /api/users` - Get list of registered users

## Security Features

- Private keys never leave the client
- All messages encrypted end-to-end
- Passphrase-protected private key storage
- No plaintext messages stored on server
- Real-time message delivery with Socket.IO

## Development Status

This is the initial project structure. The following tasks are planned:
1. ✅ Setup Project Structure and Dependencies
2. 🔄 Build User Registration and Key Management
3. ⏳ Create Message Encryption and Sending System
4. ⏳ Build Message Receiving and Decryption System
5. ⏳ Add Real-time Messaging with WebSockets
6. ⏳ Create UI Components and Pages
