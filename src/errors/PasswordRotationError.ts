export class PasswordRotationError extends Error {
  constructor(message: string = "Failed to rotate password: incorrect old password or corrupted data.") {
    super(message);
    this.name = "PasswordRotationError";
  }
};