import { DecryptionError } from "../errors/DecryptionError";
import { DecryptGeneratedKeyParams, DecryptGeneratedKeyResult } from "../types/types";
import { base64ToUint8Array } from "../utils/encoding";
import argon2 from "../config/argon2";
import { resetAttempts, trackFailedAttempt } from "../utils/attemptTracker";
import { defaultArgonConfig } from "../config/defaultArgonConfig";


export const decryptGeneratedKey = async ({
  salt,
  iv,
  encryptedKey,
  password,
  argonConfig,
  trackAttempts,
}: DecryptGeneratedKeyParams): Promise<DecryptGeneratedKeyResult> => {
  
  try {
    const saltBytes = base64ToUint8Array(salt);
    const ivBytes = base64ToUint8Array(iv);
    const encryptedVaultKey = base64ToUint8Array(encryptedKey);

    // Derive key using Argon2id
    const { hash: derivedKey } = await argon2.hash({
      pass: password,
      salt: saltBytes,
      time: argonConfig?.time ?? defaultArgonConfig.time,
      mem: argonConfig?.mem ?? defaultArgonConfig.mem,
      hashLen: argonConfig?.hashLen ?? defaultArgonConfig.hashLen,
      type: argon2.ArgonType.Argon2id,
    });

    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      derivedKey,
      'AES-GCM',
      false,
      ['decrypt']
    );

    // Decryption
    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: ivBytes },
      cryptoKey,
      encryptedVaultKey
    );
    const decryptedKey = new Uint8Array(decryptedBuffer);

    if (trackAttempts?.enable) {
      resetAttempts(trackAttempts.id);
    };


    return { success: true, decryptedKey, attempts: 0 };
  } catch {
    if (trackAttempts?.enable) {
      const { attempts } = trackFailedAttempt({
        id: trackAttempts.id,
        maxAttempts: trackAttempts.maxAttempts,
      });

      return { success: false, error: new DecryptionError(), attempts };
    };

    return { success: false, error: new DecryptionError() };
  }

};