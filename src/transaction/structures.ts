import { concatBytes } from '../utils/hex.js';
import {
  serCompactSize,
  serString,
  serUint32,
  serInt64,
  serByte,
} from './serialize.js';

/**
 * Transaction outpoint (reference to a previous output)
 */
export interface COutPoint {
  txid: Uint8Array; // 32 bytes, internal byte order (reversed from display)
  n: number; // output index
}

/**
 * Transaction input
 */
export interface CTxIn {
  prevout: COutPoint;
  scriptSig: Uint8Array;
  sequence: number;
}

/**
 * Transaction output
 */
export interface CTxOut {
  value: bigint; // in duffs
  scriptPubKey: Uint8Array;
}

/**
 * Asset lock payload (for type 8 transactions)
 */
export interface CAssetLockPayload {
  version: number;
  creditOutputs: CTxOut[];
}

/**
 * Serialize an outpoint
 */
export function serializeOutPoint(outpoint: COutPoint): Uint8Array {
  return concatBytes(outpoint.txid, serUint32(outpoint.n));
}

/**
 * Serialize a transaction input
 */
export function serializeTxIn(txin: CTxIn): Uint8Array {
  return concatBytes(
    serializeOutPoint(txin.prevout),
    serString(txin.scriptSig),
    serUint32(txin.sequence)
  );
}

/**
 * Serialize a transaction output
 */
export function serializeTxOut(txout: CTxOut): Uint8Array {
  return concatBytes(serInt64(txout.value), serString(txout.scriptPubKey));
}

/**
 * Serialize an asset lock payload
 */
export function serializeAssetLockPayload(
  payload: CAssetLockPayload
): Uint8Array {
  const parts: Uint8Array[] = [serByte(payload.version)];

  // Credit outputs as a vector
  parts.push(serCompactSize(payload.creditOutputs.length));
  for (const output of payload.creditOutputs) {
    parts.push(serializeTxOut(output));
  }

  return concatBytes(...parts);
}

/**
 * Create a P2PKH script: OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
 */
export function createP2PKHScript(pubKeyHash: Uint8Array): Uint8Array {
  if (pubKeyHash.length !== 20) {
    throw new Error('Public key hash must be 20 bytes');
  }
  return new Uint8Array([
    0x76, // OP_DUP
    0xa9, // OP_HASH160
    0x14, // Push 20 bytes
    ...pubKeyHash,
    0x88, // OP_EQUALVERIFY
    0xac, // OP_CHECKSIG
  ]);
}

/**
 * Create an OP_RETURN script for asset lock burn output
 */
export function createOpReturnScript(): Uint8Array {
  // OP_RETURN (0x6a) followed by push 0 bytes (0x00)
  return new Uint8Array([0x6a, 0x00]);
}
