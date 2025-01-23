import CryptoJS from "crypto-js";
import { ec as EC } from "elliptic";

class ISWCryptoUtils {
  private ec: any;

  constructor() {
    this.ec = new EC("p256"); // Use the P-256 elliptic curve
  }

  // Generate a random nonce (hex string)
  generateNonce(): string {
    return CryptoJS.lib.WordArray.random(16).toString(CryptoJS.enc.Hex);
  }

  // Generate an ECDH key pair
  generateECDHKeyPair(): { publicKey: string; privateKey: string } {
    const keyPair = this.ec.genKeyPair();
    return {
      publicKey: keyPair.getPublic("hex"),
      privateKey: keyPair.getPrivate("hex"),
    };
  }

  // Perform ECDH key exchange
  doECDH(privateKey: string, publicKey: string): string {
    const privateKeyPair = this.ec.keyFromPrivate(privateKey, "hex");
    const publicKeyPair = this.ec.keyFromPublic(publicKey, "hex");
    const sharedSecret = privateKeyPair.derive(publicKeyPair.getPublic());
    return sharedSecret.toString(16); // Return as hex string
  }

  // Hash a message using SHA-256
  hashMessage(message: string): string {
    return CryptoJS.SHA256(message).toString(CryptoJS.enc.Hex);
  }

  // Encrypt data using AES-256-CBC (as per your implementation)
  encryptAES(encryptableValue: string, sessionKey: string): string {
    const iv = CryptoJS.enc.Hex.parse("00000000000000000000000000000000"); // 16 bytes of zeros
    const key = CryptoJS.enc.Hex.parse(sessionKey);

    const encrypted = CryptoJS.AES.encrypt(encryptableValue, key, {
      iv: iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    });

    // Combine IV and the ciphertext
    const combinedBuffer = CryptoJS.lib.WordArray.create(
      iv.words.concat(encrypted.ciphertext.words)
    );

    // Convert to Base64 for the final result
    return CryptoJS.enc.Base64.stringify(combinedBuffer);
  }

  // Decrypt data using AES-256-CBC (corrected implementation)
  decryptAES(encryptedValue: string, sessionKey: string): string {
    const combinedBuffer = CryptoJS.enc.Base64.parse(encryptedValue);
    const iv = CryptoJS.lib.WordArray.create(combinedBuffer.words.slice(0, 4));
    const ciphertext = CryptoJS.lib.WordArray.create(
      combinedBuffer.words.slice(4),
      combinedBuffer.sigBytes - 16
    );

    const key = CryptoJS.enc.Hex.parse(sessionKey);

    // Create a CipherParams object
    const cipherParams = CryptoJS.lib.CipherParams.create({
      ciphertext: ciphertext,
      key: key,
      iv: iv,
      algorithm: CryptoJS.algo.AES,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    });

    // Decrypt using the CipherParams object
    const decrypted = CryptoJS.AES.decrypt(cipherParams, key, {
      iv: iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    });

    return CryptoJS.enc.Utf8.stringify(decrypted);
  }

  // Generate a random IV for AES encryption
  generateIV(): string {
    return CryptoJS.lib.WordArray.random(16).toString(CryptoJS.enc.Hex);
  }

  // Sign a message using ECDSA
  signMessage(message: string, privateKey: string): string {
    const keyPair = this.ec.keyFromPrivate(privateKey, "hex");
    const signature = keyPair.sign(this.hashMessage(message), "hex", { canonical: true });
    return signature.toDER("hex");
  }

  // Verify a message signature using ECDSA
  verifySignature(message: string, signature: string, publicKey: string): boolean {
    const keyPair = this.ec.keyFromPublic(publicKey, "hex");
    return keyPair.verify(this.hashMessage(message), signature);
  }
}

export default ISWCryptoUtils;

// Export for CommonJS
if (typeof module !== "undefined" && module.exports) {
  module.exports = ISWCryptoUtils;
}