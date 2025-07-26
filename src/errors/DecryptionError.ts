export class DecryptionError extends Error {
  constructor(message: string = "Decryption failed: possibly wrong master password or corrupted data.") {
    super(message);
    this.name = "DecryptionError";
  }
};