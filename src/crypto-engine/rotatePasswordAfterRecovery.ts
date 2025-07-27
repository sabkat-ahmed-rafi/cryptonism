import { uint8ArrayToBase64 } from "../utils/encoding";
import argon2 from "../config/argon2";
import { ArgonOptions } from "../types/types";

export const rotatePasswordAfterRecovery = async (
  recoveredDataKey: Uint8Array, // decrypted key from recovery
  newPassword: string,
  options?: ArgonOptions
): Promise<{
  encryptedKey: string;
  salt: string;
  iv: string;
}> => {
  // 1. Generate new salt and IV
  const newSalt = crypto.getRandomValues(new Uint8Array(32));
  const newIV = crypto.getRandomValues(new Uint8Array(12));

  // 2. Derive key from new password
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

  // 3. Re-encrypt recovered key
  const encryptedDataKeyBuffer = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: newIV },
    newCryptoKey,
    recoveredDataKey
  );

  const encryptedKey = new Uint8Array(encryptedDataKeyBuffer);

  return {
    encryptedKey: uint8ArrayToBase64(encryptedKey),
    salt: uint8ArrayToBase64(newSalt),
    iv: uint8ArrayToBase64(newIV),
  };
};
