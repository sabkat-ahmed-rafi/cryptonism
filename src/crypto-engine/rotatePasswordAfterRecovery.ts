import { uint8ArrayToBase64 } from "../utils/encoding";
import argon2 from "../config/argon2";
import { 
  rotatePasswordAfterRecoveryParams, 
  rotatePasswordAfterRecoveryResults
} from "../types/types";
import { defaultArgonConfig } from "../config/defaultArgonConfig";

export const rotatePasswordAfterRecovery = async ({
  recoveredDecryptedKey,
  newPassword,
  argonConfig 
}: rotatePasswordAfterRecoveryParams
): Promise<rotatePasswordAfterRecoveryResults> => {
  // 1. Generate new salt and IV
  const newSalt = crypto.getRandomValues(new Uint8Array(32));
  const newIV = crypto.getRandomValues(new Uint8Array(12));

  // 2. Derive key from new password
  const { hash: newDerivedKey } = await argon2.hash({
    pass: newPassword,
    salt: newSalt,
    time: argonConfig?.time ?? defaultArgonConfig.time,
    mem: argonConfig?.mem ?? defaultArgonConfig.mem,
    hashLen: argonConfig?.hashLen ?? defaultArgonConfig.hashLen,
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
    recoveredDecryptedKey
  );

  const encryptedKey = new Uint8Array(encryptedDataKeyBuffer);

  return {
    encryptedKey: uint8ArrayToBase64(encryptedKey),
    salt: uint8ArrayToBase64(newSalt),
    iv: uint8ArrayToBase64(newIV),
  };
};
