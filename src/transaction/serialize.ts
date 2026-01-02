import { concatBytes } from '../utils/hex.js';

/**
 * Serialize a compact size integer (variable length)
 */
export function serCompactSize(n: number): Uint8Array {
  if (n < 253) {
    return new Uint8Array([n]);
  } else if (n < 0x10000) {
    const buf = new Uint8Array(3);
    buf[0] = 253;
    new DataView(buf.buffer).setUint16(1, n, true);
    return buf;
  } else if (n < 0x100000000) {
    const buf = new Uint8Array(5);
    buf[0] = 254;
    new DataView(buf.buffer).setUint32(1, n, true);
    return buf;
  } else {
    const buf = new Uint8Array(9);
    buf[0] = 255;
    new DataView(buf.buffer).setBigUint64(1, BigInt(n), true);
    return buf;
  }
}

/**
 * Serialize a variable length string/bytes
 */
export function serString(data: Uint8Array): Uint8Array {
  return concatBytes(serCompactSize(data.length), data);
}

/**
 * Serialize a 32-bit unsigned integer (little-endian)
 */
export function serUint32(n: number): Uint8Array {
  const buf = new Uint8Array(4);
  new DataView(buf.buffer).setUint32(0, n, true);
  return buf;
}

/**
 * Serialize a 32-bit signed integer (little-endian)
 */
export function serInt32(n: number): Uint8Array {
  const buf = new Uint8Array(4);
  new DataView(buf.buffer).setInt32(0, n, true);
  return buf;
}

/**
 * Serialize a 64-bit signed integer (little-endian)
 */
export function serInt64(n: bigint): Uint8Array {
  const buf = new Uint8Array(8);
  new DataView(buf.buffer).setBigInt64(0, n, true);
  return buf;
}

/**
 * Serialize a single byte
 */
export function serByte(n: number): Uint8Array {
  return new Uint8Array([n & 0xff]);
}
