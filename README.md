# Secure Messaging Simulator

A full-stack cryptography learning and demo platform for secure messaging, cryptographic algorithms, and performance analysis. Built with Node.js, Express, Socket.io, and a modern interactive frontend.

## Features

### 1. Interactive Simulation
- Step-by-step simulation of secure message transmission between Alice and Bob.
- Visual flowchart for each encryption algorithm, dynamically highlights the current step.
- MITM (Man-in-the-Middle) attack simulation: tamper with ciphertext and observe signature verification failure.
- Explanations for each cryptographic step: key generation, hashing, signing, encryption, transmission, decryption, and verification.

### 2. Live Encrypted Chat
- Real-time group and private chat using Socket.io.
- End-to-end encryption for private messages (RSA/AES hybrid).
- Digital signatures for message authenticity.
- Inspect modal to view message, hash, ciphertext, signature, and encrypted session key.

### 3. Performance Analysis
- Benchmark and compare cryptographic algorithms (RSA, ECC, AES, Caesar, Shift, Transposition, Affine, etc.).
- Visual charts for operation time, throughput, and key size vs. performance.
- Tabular results for all tested algorithms and message sizes.

## Cryptographic Algorithms Implemented

### Modern Algorithms
- **RSA**: Asymmetric encryption and digital signatures. Key generation, encryption/decryption, and signing/verification using [jsencrypt](https://github.com/travist/jsencrypt).
- **ECC (Elliptic Curve Cryptography)**: Key exchange (ECDH) and digital signatures using [elliptic](https://github.com/indutny/elliptic).
- **AES**: Symmetric encryption using [crypto-js](https://github.com/brix/crypto-js).

### Classic Ciphers
- **Caesar Cipher**: Simple letter shift (implemented in JS, no external lib).
- **Shift Cipher**: Byte-wise shift (implemented in JS).
- **Transposition Cipher**: Columnar transposition (implemented in JS).
- **Affine Cipher**: Mathematical letter mapping (implemented in JS).

### Hash Functions
- **SHA-256, SHA-512, SHA-3**: [crypto-js](https://github.com/brix/crypto-js).
- **Whirlpool**: [crypto-js](https://github.com/brix/crypto-js).

## Node Modules & Libraries Used
- **express**: Web server
- **socket.io**: Real-time communication
- **crypto-js**: Hashing and symmetric encryption
- **jsencrypt**: RSA encryption/signing
- **elliptic**: ECC keygen/signing/ECDH
- **chart.js**: Performance charts
- **tailwindcss**: UI styling

## Project Structure
```
Message/
├── package.json
├── server.js
├── src/
│   ├── public/
│   │   ├── index.html
│   │   ├── css/
│   │   │   └── style.css
│   │   └── js/
│   │       └── script.js
│   └── views/
└── README.md
```

## How Each Algorithm is Implemented

### RSA
- Key generation, encryption, and signing via `jsencrypt`.
- Used for both simulation and private chat session key exchange.

### ECC
- Key generation and ECDH shared secret via `elliptic`.
- Used for simulation and can be extended for chat.

### AES
- Symmetric encryption for message confidentiality via `crypto-js`.
- Used in simulation and chat (with random session key).

### Caesar, Shift, Transposition, Affine
- All implemented in pure JavaScript in `script.js`.
- Used for educational demonstration in simulation and performance analysis.

### Hashing
- SHA-256, SHA-512, SHA-3, Whirlpool via `crypto-js`.
- Used for message integrity and digital signatures.

## How to Run
1. Install dependencies:
   ```bash
   npm install
   ```
2. Start the server:
   ```bash
   node server.js
   ```
3. Open your browser at `http://localhost:3000` (or the port shown in the terminal).

## Educational Value
- Visualizes the entire secure messaging process, including classic and modern cryptography.
- Lets users experiment with attacks and see real-time effects.
- Performance tab helps understand trade-offs between security and speed.
- All classic ciphers are implemented from scratch for learning purposes.

## Authors & Credits
- Project by Sushant Kuril and contributors.
- Uses open-source libraries as listed above.

---

For any questions or contributions, please open an issue or pull request.
