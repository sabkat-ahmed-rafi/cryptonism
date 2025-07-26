// Before store in DB
export function uint8ArrayToBase64(arr: Uint8Array): string {
  return btoa(String.fromCharCode.apply(null, Array.from(arr)));
}

// After extracting from DB
export function base64ToUint8Array(base64: string): Uint8Array {
  return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}