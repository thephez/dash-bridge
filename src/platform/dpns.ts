import { EvoSDK } from '@dashevo/evo-sdk';
import type { DpnsUsernameEntry, DpnsRegistrationResult, IdentityPublicKeyInfo } from '../types.js';

/**
 * Fetch an identity's public keys from the network
 */
export async function getIdentityPublicKeys(
  identityId: string,
  network: 'testnet' | 'mainnet'
): Promise<IdentityPublicKeyInfo[]> {
  const sdk = network === 'mainnet' ? EvoSDK.mainnetTrusted() : EvoSDK.testnetTrusted();

  console.log(`Connecting to ${network} to fetch identity ${identityId}...`);
  await sdk.connect();

  try {
    // Use getKeys to fetch all public keys for the identity
    const keysResponse = await sdk.identities.getKeys({
      identityId,
      keyRequestType: 'all',
    });

    console.log('Keys response:', keysResponse);

    if (!keysResponse) {
      throw new Error('Identity not found');
    }

    // Handle different response formats
    const keysArray = Array.isArray(keysResponse) ? keysResponse : [keysResponse];

    if (keysArray.length === 0) {
      throw new Error('Identity has no keys');
    }

    // Convert the keys to our format
    const result: IdentityPublicKeyInfo[] = [];

    for (const key of keysArray) {
      console.log('Processing key:', key);

      // Handle SDK response format: keyId, keyType, publicKeyData, purpose, securityLevel
      const id = key.keyId ?? key.id ?? 0;

      // Convert keyType string to number
      const typeStr = key.keyType ?? key.type ?? 'ECDSA_SECP256K1';
      const type = typeStr === 'ECDSA_SECP256K1' ? 0 : typeStr === 'ECDSA_HASH160' ? 2 : 0;

      // Convert purpose string to number
      const purposeStr = key.purpose ?? 'AUTHENTICATION';
      const purposeMap: Record<string, number> = {
        'AUTHENTICATION': 0, 'ENCRYPTION': 1, 'DECRYPTION': 2,
        'TRANSFER': 3, 'OWNER': 4, 'VOTING': 5
      };
      const purpose = purposeMap[purposeStr] ?? 0;

      // Convert securityLevel string to number
      const levelStr = key.securityLevel ?? 'MASTER';
      const levelMap: Record<string, number> = {
        'MASTER': 0, 'CRITICAL': 1, 'HIGH': 2, 'MEDIUM': 3
      };
      const securityLevel = levelMap[levelStr] ?? 0;

      // Get public key data - SDK returns it as publicKeyData (hex string)
      const rawData = key.publicKeyData ?? key.data;

      // Convert data to Uint8Array safely
      let data: Uint8Array;
      if (rawData instanceof Uint8Array) {
        data = rawData;
      } else if (typeof rawData === 'string') {
        // Hex encoded public key
        if (/^[0-9a-fA-F]+$/.test(rawData)) {
          data = new Uint8Array(rawData.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));
        } else {
          // Try base64
          data = new Uint8Array(atob(rawData).split('').map(c => c.charCodeAt(0)));
        }
      } else if (rawData && typeof rawData === 'object') {
        data = new Uint8Array(Object.values(rawData));
      } else {
        console.warn('Unexpected key data format:', rawData);
        data = new Uint8Array(0);
      }

      result.push({
        id,
        type,
        purpose,
        securityLevel,
        data,
      });
    }

    console.log('Parsed keys:', result);
    return result;
  } finally {
    // SDK doesn't need explicit cleanup
  }
}

/**
 * Validate a DPNS label according to platform rules:
 * - 3-63 characters
 * - Alphanumeric first and last character
 * - Hyphens allowed in middle (no consecutive hyphens)
 * - Lowercase only (will be normalized)
 */
export function validateDpnsLabel(label: string): { isValid: boolean; error?: string } {
  if (!label) {
    return { isValid: false, error: 'Username is required' };
  }

  const normalized = label.toLowerCase();

  if (normalized.length < 3) {
    return { isValid: false, error: 'Minimum 3 characters' };
  }

  if (normalized.length > 63) {
    return { isValid: false, error: 'Maximum 63 characters' };
  }

  // Must start with alphanumeric
  if (!/^[a-z0-9]/.test(normalized)) {
    return { isValid: false, error: 'Must start with letter or number' };
  }

  // Must end with alphanumeric
  if (!/[a-z0-9]$/.test(normalized)) {
    return { isValid: false, error: 'Must end with letter or number' };
  }

  // Only alphanumeric and hyphens allowed
  if (!/^[a-z0-9-]+$/.test(normalized)) {
    return { isValid: false, error: 'Only letters, numbers, and hyphens allowed' };
  }

  // No consecutive hyphens
  if (/--/.test(normalized)) {
    return { isValid: false, error: 'No consecutive hyphens allowed' };
  }

  return { isValid: true };
}

/**
 * Convert label to homograph-safe form
 * o -> 0, i -> 1, l -> 1
 */
export function convertToHomographSafe(label: string): string {
  return label
    .toLowerCase()
    .replace(/o/g, '0')
    .replace(/[il]/g, '1');
}

/**
 * Determine if a username is contested
 * Contested: 3-19 chars, only contains [a-z, 0, 1, -] after normalization
 * Non-contested: 20+ chars OR contains digits 2-9
 */
export function isContestedUsername(normalizedLabel: string): boolean {
  // 20+ chars is always non-contested
  if (normalizedLabel.length >= 20) {
    return false;
  }

  // Contains digits 2-9 is non-contested
  if (/[2-9]/.test(normalizedLabel)) {
    return false;
  }

  // 3-19 chars with only [a-z, 0, 1, -] is contested
  return /^[a-z01-]+$/.test(normalizedLabel);
}

/**
 * Create a validated username entry from a label
 */
export function createUsernameEntry(label: string): DpnsUsernameEntry {
  const normalized = convertToHomographSafe(label);
  const validation = validateDpnsLabel(label);

  return {
    label,
    normalizedLabel: normalized,
    isValid: validation.isValid,
    validationError: validation.error,
    isContested: validation.isValid ? isContestedUsername(normalized) : undefined,
    status: validation.isValid ? 'pending' : 'invalid',
  };
}

/**
 * Create an empty username entry
 */
export function createEmptyUsernameEntry(): DpnsUsernameEntry {
  return {
    label: '',
    normalizedLabel: '',
    isValid: false,
    status: 'pending',
  };
}

/**
 * Check if a username is available on the network
 */
export async function checkUsernameAvailability(
  label: string,
  network: 'testnet' | 'mainnet'
): Promise<boolean> {
  // Must use trusted mode for WASM SDK
  const sdk = network === 'mainnet' ? EvoSDK.mainnetTrusted() : EvoSDK.testnetTrusted();

  console.log(`Connecting to ${network} to check username availability...`);
  await sdk.connect();

  try {
    const isAvailable = await sdk.dpns.isNameAvailable(label);
    return isAvailable;
  } finally {
    // SDK doesn't need explicit cleanup
  }
}

/**
 * Check availability for multiple usernames
 */
export async function checkMultipleAvailability(
  entries: DpnsUsernameEntry[],
  network: 'testnet' | 'mainnet'
): Promise<DpnsUsernameEntry[]> {
  // Must use trusted mode for WASM SDK
  const sdk = network === 'mainnet' ? EvoSDK.mainnetTrusted() : EvoSDK.testnetTrusted();

  console.log(`Connecting to ${network} to check ${entries.length} username(s)...`);
  await sdk.connect();

  const results: DpnsUsernameEntry[] = [];

  // Check sequentially to avoid rate limiting
  for (const entry of entries) {
    if (!entry.isValid) {
      results.push({ ...entry, status: 'invalid' });
      continue;
    }

    try {
      console.log(`Checking availability of "${entry.label}"...`);
      const isAvailable = await sdk.dpns.isNameAvailable(entry.label);

      results.push({
        ...entry,
        isAvailable,
        status: isAvailable ? 'available' : 'taken',
      });
    } catch (error) {
      console.error(`Error checking ${entry.label}:`, error);
      // Assume taken on error to be safe
      results.push({
        ...entry,
        isAvailable: false,
        status: 'taken',
        validationError: error instanceof Error ? error.message : 'Check failed',
      });
    }
  }

  return results;
}

/**
 * Register a DPNS username
 */
export async function registerDpnsName(
  label: string,
  identityId: string,
  publicKeyId: number,
  privateKeyWif: string,
  network: 'testnet' | 'mainnet',
  onPreorder?: () => void
): Promise<{ success: boolean; isContested: boolean; error?: string }> {
  // Use trusted mode for registration (requires identity fetch)
  const sdk = network === 'mainnet'
    ? EvoSDK.mainnetTrusted()
    : EvoSDK.testnetTrusted();

  console.log(`Connecting to ${network} for DPNS registration...`);
  await sdk.connect();

  try {
    console.log(`Registering username "${label}" for identity ${identityId}...`);

    await sdk.dpns.registerName({
      label,
      identityId,
      publicKeyId,
      privateKeyWif,
      onPreorder: onPreorder ? () => onPreorder() : undefined,
    });

    const normalized = convertToHomographSafe(label);
    return {
      success: true,
      isContested: isContestedUsername(normalized),
    };
  } catch (error) {
    console.error(`Failed to register "${label}":`, error);
    return {
      success: false,
      isContested: isContestedUsername(convertToHomographSafe(label)),
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Register multiple usernames sequentially
 */
export async function registerMultipleNames(
  entries: DpnsUsernameEntry[],
  identityId: string,
  publicKeyId: number,
  privateKeyWif: string,
  network: 'testnet' | 'mainnet',
  onProgress?: (current: number, total: number, label: string) => void
): Promise<DpnsRegistrationResult[]> {
  const results: DpnsRegistrationResult[] = [];

  // Filter to only available usernames
  const availableEntries = entries.filter((e) => e.isValid && e.isAvailable);

  for (let i = 0; i < availableEntries.length; i++) {
    const entry = availableEntries[i];
    onProgress?.(i + 1, availableEntries.length, entry.label);

    const result = await registerDpnsName(
      entry.label,
      identityId,
      publicKeyId,
      privateKeyWif,
      network
    );

    results.push({
      label: entry.label,
      success: result.success,
      error: result.error,
      isContested: entry.isContested ?? false,
    });
  }

  return results;
}

/**
 * Check if all available usernames in a list are contested
 * Used to determine if warning should be shown
 */
export function shouldShowContestedWarning(usernames: DpnsUsernameEntry[]): boolean {
  const validAvailable = usernames.filter((u) => u.isValid && u.isAvailable);

  // No valid available names - no warning needed
  if (validAvailable.length === 0) {
    return false;
  }

  // All valid+available names are contested
  return validAvailable.every((u) => u.isContested);
}

/**
 * Count of each username status category
 */
export function countUsernameStatuses(usernames: DpnsUsernameEntry[]): {
  available: number;
  taken: number;
  invalid: number;
  contested: number;
  nonContested: number;
} {
  const available = usernames.filter((u) => u.isValid && u.isAvailable).length;
  const taken = usernames.filter((u) => u.isValid && u.isAvailable === false).length;
  const invalid = usernames.filter((u) => !u.isValid).length;
  const contested = usernames.filter((u) => u.isValid && u.isAvailable && u.isContested).length;
  const nonContested = usernames.filter((u) => u.isValid && u.isAvailable && !u.isContested).length;

  return { available, taken, invalid, contested, nonContested };
}
