import { ArgonOptions } from "../types/types";
import { uint8ArrayToBase64 } from "../utils/encoding";
import argon2 from 'argon2-browser/dist/argon2-bundled.min.js';



export const generateEncryptedKey = async (
    password: string,
    options?: ArgonOptions
) => {
    // 1. Generate random salt (32 bytes)
    const salt = crypto.getRandomValues(new Uint8Array(32));

    // 2. Derive key from password using Argon2id
    const { hash: derivedKey } = await argon2.hash({
        pass: password,
        salt,
        time: options?.time ?? 3,
        mem: options?.mem ?? 65536,
        hashLen: options?.hashLen ?? 32,
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
    const encryptedKeyUint8 = new Uint8Array(encryptedKeyArrayBuffer);

    return {
        encryptedKey: uint8ArrayToBase64(encryptedKeyUint8),
        salt: uint8ArrayToBase64(salt),
        iv: uint8ArrayToBase64(iv),
    }

};