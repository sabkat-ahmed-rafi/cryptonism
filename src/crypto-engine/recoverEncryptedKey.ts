import { RecoverEncryptionError } from "../errors/RecoverEncryptionError";
import { RecoverEncryptedKeyParams, RecoverEncryptedKeyResult } from "../types/types";
import { base64ToUint8Array } from "../utils/encoding";
import argon2 from "../config/argon2";
import { defaultArgonConfig } from "../config/defaultArgonConfig";

export const recoverEncryptedKey = async (
  { recoveryMnemonic,
    encryptedRecoveryKey,
    recoverySalt,
    recoveryIV,
    argonConfig
  }: RecoverEncryptedKeyParams
): Promise<RecoverEncryptedKeyResult> => {
  try {
  const salt = base64ToUint8Array(recoverySalt);
  const iv = base64ToUint8Array(recoveryIV);
  const encryptedKey = base64ToUint8Array(encryptedRecoveryKey);

  const { hash: derivedKey } = await argon2.hash({
    pass: recoveryMnemonic,
    salt,
    time: argonConfig?.time ?? defaultArgonConfig.time,
    mem: argonConfig?.mem ?? defaultArgonConfig.mem,
    hashLen: argonConfig?.hashLen ?? defaultArgonConfig.hashLen,
    type: argon2.ArgonType.Argon2id,
  });

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    derivedKey,
    "AES-GCM",
    false,
    ["decrypt"]
  );

    const decryptedKeyBuffer = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      cryptoKey,
      encryptedKey
    );
    
    const decryptedKey = new Uint8Array(decryptedKeyBuffer);
    
    return { success: true, decryptedKey: decryptedKey };
  } catch {
    return { success: false, error: new RecoverEncryptionError() };
  }
};
