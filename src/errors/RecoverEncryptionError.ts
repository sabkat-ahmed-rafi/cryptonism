export class RecoverEncryptionError extends Error {
  constructor(message: string = "Recovery failed: invalid recovery phrase or corrupted recovery data.") {
    super(message);
    this.name = "RecoverEncryptionError";
  }
};