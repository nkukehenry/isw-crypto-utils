const CryptoJS   = require("crypto-js");
const { ec: EC } = require("elliptic");

class ISWCryptoUtils {
  private ec;

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

  // Encrypt data using AES-256-CBC
  encryptAES(data: string, key: string, iv: string): string {
    const encrypted = CryptoJS.AES.encrypt(data, CryptoJS.enc.Hex.parse(key), {
      iv: CryptoJS.enc.Hex.parse(iv),
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    });
    return encrypted.toString();
  }

  // Decrypt data using AES-256-CBC
  decryptAES(encryptedData: string, key: string, iv: string): string {
    const decrypted = CryptoJS.AES.decrypt(encryptedData, CryptoJS.enc.Hex.parse(key), {
      iv: CryptoJS.enc.Hex.parse(iv),
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    });
    return decrypted.toString(CryptoJS.enc.Utf8);
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