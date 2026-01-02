import { hash160 } from './hash.js';
import { base58CheckEncode } from '../utils/base58.js';
import { concatBytes } from '../utils/hex.js';
import type { NetworkConfig } from '../config.js';

/**
 * Generate P2PKH address from public key
 */
export function publicKeyToAddress(
  publicKey: Uint8Array,
  network: NetworkConfig
): string {
  const pubKeyHash = hash160(publicKey);
  const versionedHash = concatBytes(
    new Uint8Array([network.addressPrefix]),
    pubKeyHash
  );
  return base58CheckEncode(versionedHash);
}

/**
 * Get pubkey hash from public key
 */
export function publicKeyToHash(publicKey: Uint8Array): Uint8Array {
  return hash160(publicKey);
}
