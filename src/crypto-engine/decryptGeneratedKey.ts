import { DecryptionError } from "../errors/DecryptionError";
import { ArgonOptions } from "../types/types";
import { base64ToUint8Array } from "../utils/encoding";
import argon2 from "../config/argon2";
import { resetAttempts, trackFailedAttempt } from "../utils/attemptTracker";


export const decryptGeneratedKey = async (  
  base64Salt: string,
  base64IV: string,
  base64EncryptedVaultKey: string,
  password: string,
  options?: ArgonOptions,
  trackAttempts?: {
    enable: true;
    id: string;
    maxAttempts: number;
  }
): Promise<{
  decryptedKey?: Uint8Array;
  attempts?: number;
  error?: DecryptionError;
}> => {

  const salt = base64ToUint8Array(base64Salt);
  const iv = base64ToUint8Array(base64IV);
  const encryptedVaultKey = base64ToUint8Array(base64EncryptedVaultKey);

  // Derive key using Argon2id
  const { hash: derivedKey } = await argon2.hash({
    pass: password,
    salt,
    time: options?.time ?? 3,
    mem: options?.mem ?? 65536,
    hashLen: options?.hashLen ?? 32,
    type: argon2.ArgonType.Argon2id,
  });

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    derivedKey,
    'AES-GCM',
    false,
    ['decrypt']
  );

  try {
    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      cryptoKey,
      encryptedVaultKey
    );
    const decryptedKey = new Uint8Array(decryptedBuffer);

    if (trackAttempts?.enable) {
      resetAttempts(trackAttempts.id);
    };


    return { decryptedKey, attempts: 0 };
  } catch {
    if (trackAttempts?.enable) {
      const { attempts } = trackFailedAttempt({
        id: trackAttempts.id,
        maxAttempts: trackAttempts.maxAttempts,
      });

      return {
        error: new DecryptionError(),
        attempts,
      };
    }

    return { error: new DecryptionError() };
  }

};