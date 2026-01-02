import { bytesToHex } from '../utils/hex.js';

/**
 * InstantAssetLockProof structure as expected by the Platform SDK
 */
export interface InstantAssetLockProof {
  instantLock: string; // base64-encoded
  transaction: string; // base64-encoded
  outputIndex: number;
}

/**
 * Encode bytes to base64
 */
function base64Encode(data: Uint8Array): string {
  // Use browser's btoa with proper handling of binary data
  let binary = '';
  for (let i = 0; i < data.length; i++) {
    binary += String.fromCharCode(data[i]);
  }
  return btoa(binary);
}

/**
 * Build an InstantAssetLockProof from transaction and instant lock bytes
 *
 * The proof format matches what the platform-identity-faucet produces
 * in app/services/proof_builder.py
 *
 * @param transactionBytes - Serialized signed transaction
 * @param instantLockBytes - Serialized InstantSend lock message
 * @param outputIndex - Index of the burn output (usually 0)
 * @returns Hex-encoded JSON proof string for EvoSDK
 */
export function buildInstantAssetLockProof(
  transactionBytes: Uint8Array,
  instantLockBytes: Uint8Array,
  outputIndex: number = 0
): string {
  const proof: InstantAssetLockProof = {
    instantLock: base64Encode(instantLockBytes),
    transaction: base64Encode(transactionBytes),
    outputIndex,
  };

  // Convert to JSON string
  const jsonStr = JSON.stringify(proof);

  // Hex-encode the JSON (this is what EvoSDK expects)
  const encoder = new TextEncoder();
  const jsonBytes = encoder.encode(jsonStr);

  return bytesToHex(jsonBytes);
}

/**
 * Decode a hex-encoded proof back to the proof object
 * (Useful for debugging/verification)
 */
export function decodeAssetLockProof(hexProof: string): InstantAssetLockProof {
  // Hex decode
  const bytes = new Uint8Array(hexProof.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hexProof.substr(i * 2, 2), 16);
  }

  // Decode as UTF-8 JSON
  const decoder = new TextDecoder();
  const jsonStr = decoder.decode(bytes);

  return JSON.parse(jsonStr);
}
