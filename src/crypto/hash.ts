import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';

/**
 * Single SHA256 hash
 */
export function sha256Hash(data: Uint8Array): Uint8Array {
  return sha256(data);
}

/**
 * Double SHA256 hash (used for Bitcoin/Dash txid, signature hash, etc.)
 */
export function hash256(data: Uint8Array): Uint8Array {
  return sha256(sha256(data));
}

/**
 * RIPEMD160(SHA256(data)) - used for address generation
 */
export function hash160(data: Uint8Array): Uint8Array {
  return ripemd160(sha256(data));
}
