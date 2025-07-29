import { EncryptionError } from "../errors/EncryptionError";
import { EncryptedSecretResult, EncryptSecretParams } from "../types/types";
import { uint8ArrayToBase64 } from "../utils/encoding";

export const encryptSecret = async ({
  secret,
  decryptedKey
}: EncryptSecretParams
): Promise<EncryptedSecretResult> => {
  try {
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      decryptedKey,
      "AES-GCM",
      false,
      ["encrypt"]
    );

    const encoded = new TextEncoder().encode(secret);
    const encryptedBuffer = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      cryptoKey,
      encoded
    );

    return {
      success: true,
      encryptedSecret: uint8ArrayToBase64(new Uint8Array(encryptedBuffer)),
      iv: uint8ArrayToBase64(iv),
    }
  } catch {
    return { success: false, error: new EncryptionError() }
  }
};
