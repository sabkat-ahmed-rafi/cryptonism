export class DecryptionError extends Error {
  constructor(message: string = "Decryption failed: possibly wrong password or corrupted data.") {
    super(message);
    this.name = "DecryptionError";
  }
};