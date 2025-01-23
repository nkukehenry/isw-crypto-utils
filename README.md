# ISW Crypto Utils

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A Node.js package providing cryptographic utilities for common tasks such as generating nonces, performing ECDH key exchange, hashing messages, encrypting/decrypting data using AES-256-CBC, and signing/verifying messages using ECDSA. Built with `crypto-js` and `elliptic`.

---

## Installation

Install the package using npm:

```bash
npm install isw-crypto-utils
```
* * * * *

Usage
-----

### Import the Package

```javascript
import ISWCryptoUtils from '../node_modules/isw-crypto-utils'
const cryptoUtils = new ISWCryptoUtils();
```
* * * * *

### Generate a Random Nonce

A nonce is a random value used in cryptographic operations. Use the `generateNonce()` method to generate a 16-byte nonce as a hex string.

```javascript
const nonce = cryptoUtils.generateNonce();
console.log("Nonce:", nonce);
```
* * * * *

### Generate an ECDH Key Pair

Generate a public/private key pair for Elliptic Curve Diffie-Hellman (ECDH) key exchange using the P-256 curve.

```javascript
const keyPair = cryptoUtils.generateECDHKeyPair();
console.log("Public Key:", keyPair.publicKey);
console.log("Private Key:", keyPair.privateKey);
```
* * * * *

### Perform ECDH Key Exchange

Derive a shared secret using ECDH. Pass your private key and the other party's public key.

```javascript
const sharedSecret = cryptoUtils.doECDH(privateKey, remotePublicKey);
console.log("Shared Secret:", sharedSecret);
```
* * * * *

### Hash a Message

Hash a message using SHA-256. The output is a hex string.

```javascript
const hash = cryptoUtils.hashMessage("Hello, World!");
console.log("Hash:", hash);
```
* * * * *

### Encrypt Data Using AES-256-CBC

Encrypt data using AES-256-CBC. You need a 256-bit key (64 hex characters).

```javascript

const key = "your-256-bit-key"; // Must be 64 hex characters
const encryptedData = cryptoUtils.encryptAES("Sensitive Data", key);
console.log("Encrypted Data:", encryptedData);
```
* * * * *

### Decrypt Data Using AES-256-CBC

Decrypt data using AES-256-CBC. Use the same key used for encryption.

```javascript
const decryptedData = cryptoUtils.decryptAES(encryptedData, key);
console.log("Decrypted Data:", decryptedData);
```

* * * * *

### Sign a Message

Sign a message using RSA. Pass the message and your private key.

```javascript
const signature = cryptoUtils.signMessage("Hello, World!", privateKey);
console.log("Signature:", signature);
```

* * * * *

### Verify a Signature

Verify a message signature using RSA. Pass the message, signature, and the signer's public key.

```javascript
const isValid = cryptoUtils.verifySignature("Hello, World!", signature, publicKey);
console.log("Signature Valid:", isValid);
```
* * * * *

API Reference
-------------

| Method | Description |
| --- | --- |
| `generateNonce()` | Generates a random 16-byte nonce as a hex string. |
| `generateECDHKeyPair()` | Generates an ECDH key pair (public and private keys) using the P-256 curve. |
| `doECDH(privateKey, publicKey)` | Derives a shared secret using ECDH key exchange. |
| `hashMessage(message)` | Hashes a message using SHA-256. |
| `encryptAES(data, key, iv)` | Encrypts data using AES-256-CBC. |
| `decryptAES(encryptedData, key, iv)` | Decrypts data using AES-256-CBC. |
| `generateIV()` | Generates a random 16-byte IV for AES encryption. |
| `signMessage(message, privateKey)` | Signs a message using RSA. |
| `verifySignature(message, signature, publicKey)` | Verifies a message signature using RSA. |

* * * * *

Dependencies
------------

-   [`crypto-js`](https://www.npmjs.com/package/crypto-js): For AES encryption/decryption, SHA-256 hashing, and random byte generation.

-   [`elliptic`](https://www.npmjs.com/package/elliptic): For ECDH key exchange and ECDSA signing/verification.

* * * * *

License
-------

This project is licensed under the MIT License. See the [LICENSE](https://chat.deepseek.com/a/chat/s/LICENSE) file for details.

* * * * *

Contributing
------------

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

* * * * *

Support
-------

If you find this package useful, consider giving it a ⭐️ on [GitHub](https://github.com/nkukehenry/isw-crypto-utils)!

