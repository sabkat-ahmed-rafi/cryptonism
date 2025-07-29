import { base64ToUint8Array } from "../utils/encoding";
import { DecryptionError } from "../errors/DecryptionError";
import { DecryptSecretParams, DecryptSecretResult } from "../types/types";

export const decryptSecret = async ({
  encryptedSecret,
  iv,
  decryptedKey
}: DecryptSecretParams
): Promise<DecryptSecretResult> => {
  try {
    const ivBytes = base64ToUint8Array(iv);
    const encryptedBytes = base64ToUint8Array(encryptedSecret);

    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      decryptedKey,
      "AES-GCM",
      false,
      ["decrypt"]
    );

    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: ivBytes },
      cryptoKey,
      encryptedBytes
    );

    const decryptedSecret = new TextDecoder().decode(decryptedBuffer);

    return { success: true,  decryptedSecret: decryptedSecret };
  } catch {
    return { success: false, error: new DecryptionError() }
  }
};
