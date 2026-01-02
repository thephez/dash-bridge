import bs58check from 'bs58check';

/**
 * Encode bytes with Base58Check
 */
export function base58CheckEncode(data: Uint8Array): string {
  return bs58check.encode(data);
}

/**
 * Decode Base58Check string to bytes
 */
export function base58CheckDecode(str: string): Uint8Array {
  return bs58check.decode(str);
}
