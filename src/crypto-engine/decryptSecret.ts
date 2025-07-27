import { base64ToUint8Array } from "../utils/encoding";
import { DecryptionError } from "../errors/DecryptionError";

export const decryptSecret = async (
  encryptedSecret: string,
  iv: string,
  decryptedKey: Uint8Array
): Promise<string> => {
  const ivBytes = base64ToUint8Array(iv);
  const encryptedBytes = base64ToUint8Array(encryptedSecret);

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    decryptedKey,
    "AES-GCM",
    false,
    ["decrypt"]
  );

  try {
    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: ivBytes },
      cryptoKey,
      encryptedBytes
    );

    return new TextDecoder().decode(decryptedBuffer);
  } catch {
    throw new DecryptionError();
  }
};
