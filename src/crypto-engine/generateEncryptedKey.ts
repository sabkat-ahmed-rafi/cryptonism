import { GenerateEncryptedKeyParams, GenerateEncryptedKeyResult } from "../types/types";
import { uint8ArrayToBase64 } from "../utils/encoding";
import argon2 from "../config/argon2";
import { entropyToMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { defaultArgonConfig } from "../config/defaultArgonConfig";



export const generateEncryptedKey = async (
  {password, argonConfig}: GenerateEncryptedKeyParams
): Promise<GenerateEncryptedKeyResult> => {
    // 1. Generate random salt (32 bytes)
    const salt = crypto.getRandomValues(new Uint8Array(32));

    // 2. Derive key from password using Argon2id
    const { hash: derivedKey } = await argon2.hash({
        pass: password,
        salt,
        time: argonConfig?.time ?? defaultArgonConfig.time,
        mem: argonConfig?.mem ?? defaultArgonConfig.mem,
        hashLen: argonConfig?.hashLen ?? defaultArgonConfig.hashLen,
        type: argon2.ArgonType.Argon2id,
    });

    // 3. Generate key (AES key, 32 bytes)
    const key = crypto.getRandomValues(new Uint8Array(32));

    // 4. Encrypt the key with AES-GCM
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        derivedKey,
        'AES-GCM',
        false,
        ['encrypt']
    );

    const encryptedKeyArrayBuffer = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        cryptoKey,
        key
    );
    const encryptedKey = new Uint8Array(encryptedKeyArrayBuffer);

      // 5. Recovery: Generate recovery key
    const recoveryKey = crypto.getRandomValues(new Uint8Array(16));
    const mnemonic = entropyToMnemonic(recoveryKey, wordlist); // 12-word phrase
    const recoverySalt = crypto.getRandomValues(new Uint8Array(32));
    const recoveryIV = crypto.getRandomValues(new Uint8Array(12));

    const { hash: recoveryDerivedKey } = await argon2.hash({
      pass: mnemonic,
      salt: recoverySalt,
      time: argonConfig?.time ?? defaultArgonConfig.time,
      mem: argonConfig?.mem ?? defaultArgonConfig.mem,
      hashLen: argonConfig?.hashLen ?? defaultArgonConfig.hashLen,
      type: argon2.ArgonType.Argon2id,
    });

    const recoveryCryptoKey = await crypto.subtle.importKey(
      "raw",
      recoveryDerivedKey,
      "AES-GCM",
      false,
      ["encrypt"]
    );
    const encryptedRecoveryKeyBuffer = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: recoveryIV },
      recoveryCryptoKey,
      key
    );

    const encryptedRecoveryKey = new Uint8Array(encryptedRecoveryKeyBuffer);

    return {
        encryptedKey: uint8ArrayToBase64(encryptedKey),
        salt: uint8ArrayToBase64(salt),
        iv: uint8ArrayToBase64(iv),

        recoveryPhrase: mnemonic, // Show this once to the user
        encryptedRecoveryKey: uint8ArrayToBase64(encryptedRecoveryKey),
        recoverySalt: uint8ArrayToBase64(recoverySalt),
        recoveryIV: uint8ArrayToBase64(recoveryIV),
    }

};