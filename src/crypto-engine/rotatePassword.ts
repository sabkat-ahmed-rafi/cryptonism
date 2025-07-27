import { base64ToUint8Array, uint8ArrayToBase64 } from "../utils/encoding";
import argon2 from "../config/argon2";
import { ArgonOptions } from "../types/types";
import { PasswordRotationError } from "../errors/PasswordRotationError";

export const rotatePassword = async (
  encryptedDataKey: string,
  oldPassword: string,
  newPassword: string,
  salt: string,
  iv: string,
  options?: ArgonOptions
): Promise<{
  encryptedDataKey: string;
  salt: string;
  iv: string;
}> => {
  // 1. Prepare inputs
  const oldSalt = base64ToUint8Array(salt);
  const oldIV = base64ToUint8Array(iv);
  const encryptedKey = base64ToUint8Array(encryptedDataKey);

  // 2. Derive key from old password
  const { hash: oldDerivedKey } = await argon2.hash({
    pass: oldPassword,
    salt: oldSalt,
    time: options?.time ?? 3,
    mem: options?.mem ?? 65536,
    hashLen: options?.hashLen ?? 32,
    type: argon2.ArgonType.Argon2id,
  });

  const oldCryptoKey = await crypto.subtle.importKey(
    "raw",
    oldDerivedKey,
    "AES-GCM",
    false,
    ["decrypt"]
  );

  // 3. Decrypt existing key using old password
  let decryptedKeyBuffer: ArrayBuffer;
  try {
    decryptedKeyBuffer = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: oldIV },
      oldCryptoKey,
      encryptedKey
    );
  } catch {
    throw new PasswordRotationError();
  }

  const decryptedKey = new Uint8Array(decryptedKeyBuffer);

  // 4. Derive new key using new password
  const newSalt = crypto.getRandomValues(new Uint8Array(32));
  const newIV = crypto.getRandomValues(new Uint8Array(12));

  const { hash: newDerivedKey } = await argon2.hash({
    pass: newPassword,
    salt: newSalt,
    time: options?.time ?? 3,
    mem: options?.mem ?? 65536,
    hashLen: options?.hashLen ?? 32,
    type: argon2.ArgonType.Argon2id,
  });

  const newCryptoKey = await crypto.subtle.importKey(
    "raw",
    newDerivedKey,
    "AES-GCM",
    false,
    ["encrypt"]
  );

  // 5. Re-encrypt the data key with the new password
  const newEncryptedDataKeyBuffer = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: newIV },
    newCryptoKey,
    decryptedKey
  );
  const newEncryptedDataKey = new Uint8Array(newEncryptedDataKeyBuffer);

  // 6. Return updated encrypted values
  return {
    encryptedDataKey: uint8ArrayToBase64(newEncryptedDataKey),
    salt: uint8ArrayToBase64(newSalt),
    iv: uint8ArrayToBase64(newIV),
  };
};
