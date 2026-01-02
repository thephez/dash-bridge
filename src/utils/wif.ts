import { base58CheckEncode, base58CheckDecode } from './base58.js';
import { concatBytes } from './hex.js';
import type { NetworkConfig } from '../config.js';

/**
 * Encode private key to WIF (Wallet Import Format)
 * For compressed public keys, append 0x01 before checksum
 */
export function privateKeyToWif(
  privateKey: Uint8Array,
  network: NetworkConfig,
  compressed: boolean = true
): string {
  const prefix = new Uint8Array([network.wifPrefix]);
  if (compressed) {
    return base58CheckEncode(concatBytes(prefix, privateKey, new Uint8Array([0x01])));
  }
  return base58CheckEncode(concatBytes(prefix, privateKey));
}

/**
 * Decode WIF to private key
 */
export function wifToPrivateKey(wif: string): {
  privateKey: Uint8Array;
  compressed: boolean;
  prefix: number;
} {
  const decoded = base58CheckDecode(wif);
  const prefix = decoded[0];

  if (decoded.length === 34 && decoded[33] === 0x01) {
    // Compressed
    return {
      privateKey: decoded.slice(1, 33),
      compressed: true,
      prefix,
    };
  } else if (decoded.length === 33) {
    // Uncompressed
    return {
      privateKey: decoded.slice(1, 33),
      compressed: false,
      prefix,
    };
  }

  throw new Error('Invalid WIF format');
}
