import { RecoverEncryptionError } from "../errors/RecoverEncryptionError";
import { ArgonOptions } from "../types/types";
import { base64ToUint8Array } from "../utils/encoding";
import argon2 from "argon2-browser/dist/argon2-bundled.min.js";

export const recoverEncryptedKey = async (
  recoveryMnemonic: string,
  encryptedRecoveryKey: string,
  recoverySalt: string,
  recoveryIV: string,
  options?: ArgonOptions
): Promise<Uint8Array> => {
  const salt = base64ToUint8Array(recoverySalt);
  const iv = base64ToUint8Array(recoveryIV);
  const encryptedKey = base64ToUint8Array(encryptedRecoveryKey);

  const { hash: derivedKey } = await argon2.hash({
    pass: recoveryMnemonic,
    salt,
    time: options?.time ?? 3,
    mem: options?.mem ?? 65536,
    hashLen: options?.hashLen ?? 32,
    type: argon2.ArgonType.Argon2id,
  });

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    derivedKey,
    "AES-GCM",
    false,
    ["decrypt"]
  );

  try {
    const decryptedKeyBuffer = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      cryptoKey,
      encryptedKey
    );
    
    const decryptedKey = new Uint8Array(decryptedKeyBuffer);
    
    return decryptedKey;
  } catch {
    throw new RecoverEncryptionError();
  }
};
