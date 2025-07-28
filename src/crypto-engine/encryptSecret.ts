import { EncryptedSecretResult, EncryptSecretParams } from "../types/types";
import { uint8ArrayToBase64 } from "../utils/encoding";

export const encryptSecret = async ({
  secret,
  decryptedKey
}: EncryptSecretParams
): Promise<EncryptedSecretResult> => {
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
    encryptedSecret: uint8ArrayToBase64(new Uint8Array(encryptedBuffer)),
    iv: uint8ArrayToBase64(iv),
  };
};
