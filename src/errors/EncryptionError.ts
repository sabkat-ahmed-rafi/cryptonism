export class EncryptionError extends Error {
  constructor(message: string = "Encryption failed: possibly corrupted data.") {
    super(message);
    this.name = "EncryptionError";
  }
};