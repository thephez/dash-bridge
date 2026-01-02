import * as secp256k1 from '@noble/secp256k1';
import { randomBytes } from '@noble/hashes/utils';
import type { KeyPair, IdentityKeyConfig, KeyType, KeyPurpose, SecurityLevel } from '../types.js';
import { hash160 } from './hash.js';
import { bytesToHex } from '../utils/hex.js';
import { privateKeyToWif } from '../utils/wif.js';
import { getNetwork } from '../config.js';
import { deriveIdentityKey as deriveIdentityKeyHD } from './hd.js';

/**
 * Generate a new secp256k1 key pair
 */
export function generateKeyPair(): KeyPair {
  const privateKey = randomBytes(32);
  const publicKey = secp256k1.getPublicKey(privateKey, true); // compressed (33 bytes)
  return { privateKey, publicKey };
}

/**
 * Get compressed public key from private key
 */
export function getPublicKey(privateKey: Uint8Array): Uint8Array {
  return secp256k1.getPublicKey(privateKey, true);
}

/**
 * Validate a private key
 */
export function isValidPrivateKey(privateKey: Uint8Array): boolean {
  try {
    secp256k1.getPublicKey(privateKey);
    return true;
  } catch {
    return false;
  }
}

/**
 * Convert bytes to base64
 */
function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Get the data bytes for SDK based on key type
 * - ECDSA_SECP256K1: full 33-byte compressed public key
 * - ECDSA_HASH160: 20-byte hash160 of the public key
 */
function getKeyDataBytes(publicKey: Uint8Array, keyType: KeyType): Uint8Array {
  if (keyType === 'ECDSA_HASH160') {
    return hash160(publicKey);
  }
  return publicKey;
}

/**
 * Generate a configured identity key
 */
export function generateIdentityKey(
  id: number,
  name: string,
  keyType: KeyType,
  purpose: KeyPurpose,
  securityLevel: SecurityLevel,
  network: 'testnet' | 'mainnet'
): IdentityKeyConfig {
  const keyPair = generateKeyPair();
  const networkConfig = getNetwork(network);
  const dataBytes = getKeyDataBytes(keyPair.publicKey, keyType);

  return {
    id,
    name,
    keyType,
    purpose,
    securityLevel,
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    privateKeyHex: bytesToHex(keyPair.privateKey),
    privateKeyWif: privateKeyToWif(keyPair.privateKey, networkConfig),
    publicKeyHex: bytesToHex(keyPair.publicKey),
    dataBase64: bytesToBase64(dataBytes),
  };
}

/**
 * Regenerate a key with new cryptographic material but same config
 */
export function regenerateIdentityKey(
  existing: IdentityKeyConfig,
  network: 'testnet' | 'mainnet'
): IdentityKeyConfig {
  return generateIdentityKey(
    existing.id,
    existing.name,
    existing.keyType,
    existing.purpose,
    existing.securityLevel,
    network
  );
}

/**
 * Update key type and regenerate data (keeps same private key)
 */
export function updateKeyType(
  existing: IdentityKeyConfig,
  newKeyType: KeyType,
  network: 'testnet' | 'mainnet'
): IdentityKeyConfig {
  const networkConfig = getNetwork(network);
  const dataBytes = getKeyDataBytes(existing.publicKey, newKeyType);

  return {
    ...existing,
    keyType: newKeyType,
    privateKeyWif: privateKeyToWif(existing.privateKey, networkConfig),
    dataBase64: bytesToBase64(dataBytes),
  };
}

/**
 * Generate default identity keys (4 keys as in faucet)
 * @deprecated Use generateDefaultIdentityKeysHD for HD derivation
 */
export function generateDefaultIdentityKeys(
  network: 'testnet' | 'mainnet'
): IdentityKeyConfig[] {
  return [
    generateIdentityKey(0, 'Master', 'ECDSA_SECP256K1', 'AUTHENTICATION', 'MASTER', network),
    generateIdentityKey(1, 'High Auth', 'ECDSA_SECP256K1', 'AUTHENTICATION', 'HIGH', network),
    generateIdentityKey(2, 'Critical Auth', 'ECDSA_SECP256K1', 'AUTHENTICATION', 'CRITICAL', network),
    generateIdentityKey(3, 'Transfer', 'ECDSA_SECP256K1', 'TRANSFER', 'CRITICAL', network),
  ];
}

/**
 * Create an IdentityKeyConfig from a provided key pair
 */
export function createIdentityKeyFromKeyPair(
  id: number,
  name: string,
  keyType: KeyType,
  purpose: KeyPurpose,
  securityLevel: SecurityLevel,
  privateKey: Uint8Array,
  publicKey: Uint8Array,
  network: 'testnet' | 'mainnet',
  derivationPath?: string
): IdentityKeyConfig {
  const networkConfig = getNetwork(network);
  const dataBytes = getKeyDataBytes(publicKey, keyType);

  return {
    id,
    name,
    keyType,
    purpose,
    securityLevel,
    privateKey,
    publicKey,
    privateKeyHex: bytesToHex(privateKey),
    privateKeyWif: privateKeyToWif(privateKey, networkConfig),
    publicKeyHex: bytesToHex(publicKey),
    dataBase64: bytesToBase64(dataBytes),
    derivationPath,
  };
}

/**
 * Generate a configured identity key using HD derivation
 */
export function generateIdentityKeyFromMnemonic(
  id: number,
  name: string,
  keyType: KeyType,
  purpose: KeyPurpose,
  securityLevel: SecurityLevel,
  network: 'testnet' | 'mainnet',
  mnemonic: string,
  keyIndex: number
): IdentityKeyConfig {
  const { privateKey, publicKey, derivationPath } = deriveIdentityKeyHD(mnemonic, keyIndex, network);

  return createIdentityKeyFromKeyPair(
    id,
    name,
    keyType,
    purpose,
    securityLevel,
    privateKey,
    publicKey,
    network,
    derivationPath
  );
}

/**
 * Generate default identity keys using HD derivation
 */
export function generateDefaultIdentityKeysHD(
  network: 'testnet' | 'mainnet',
  mnemonic: string
): IdentityKeyConfig[] {
  return [
    generateIdentityKeyFromMnemonic(0, 'Master', 'ECDSA_SECP256K1', 'AUTHENTICATION', 'MASTER', network, mnemonic, 0),
    generateIdentityKeyFromMnemonic(1, 'High Auth', 'ECDSA_SECP256K1', 'AUTHENTICATION', 'HIGH', network, mnemonic, 1),
    generateIdentityKeyFromMnemonic(2, 'Critical Auth', 'ECDSA_SECP256K1', 'AUTHENTICATION', 'CRITICAL', network, mnemonic, 2),
    generateIdentityKeyFromMnemonic(3, 'Transfer', 'ECDSA_SECP256K1', 'TRANSFER', 'CRITICAL', network, mnemonic, 3),
  ];
}
