import { concatBytes, hexToBytes } from '../utils/hex.js';
import { hash256 } from '../crypto/hash.js';
import { serUint32 } from './serialize.js';
import {
  type AssetLockTransaction,
  serializeTransaction,
  cloneTransaction,
} from './builder.js';
import type { UTXO } from '../types.js';

const SIGHASH_ALL = 0x01;

/**
 * Compute the signature hash for a transaction input
 *
 * For P2PKH, the scriptCode is the scriptPubKey of the output being spent.
 */
export function signatureHash(
  tx: AssetLockTransaction,
  inputIndex: number,
  scriptCode: Uint8Array,
  sighashType: number = SIGHASH_ALL
): Uint8Array {
  if (inputIndex >= tx.vin.length) {
    throw new Error('Input index out of range');
  }

  // Create a modified copy of the transaction
  const txCopy = cloneTransaction(tx);

  // Clear all input scripts
  for (let i = 0; i < txCopy.vin.length; i++) {
    txCopy.vin[i].scriptSig = new Uint8Array(0);
  }

  // Set the script for the input being signed
  txCopy.vin[inputIndex].scriptSig = scriptCode;

  // Serialize the modified transaction
  const txBytes = serializeTransaction(txCopy);

  // Append sighash type as 4-byte little-endian
  const sighashBytes = serUint32(sighashType);

  // Double SHA256
  return hash256(concatBytes(txBytes, sighashBytes));
}

/**
 * Get the scriptPubKey from a UTXO (for use as scriptCode in signing)
 */
export function getScriptCodeFromUtxo(utxo: UTXO): Uint8Array {
  return hexToBytes(utxo.scriptPubKey);
}

export { SIGHASH_ALL };
