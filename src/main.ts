import { getNetwork } from './config.js';
import { publicKeyToAddress, signTransaction, generateKeyPair } from './crypto/index.js';
import { deriveAssetLockKeyPair } from './crypto/hd.js';
import { createAssetLockTransaction, serializeTransaction } from './transaction/index.js';
import { InsightClient } from './api/insight.js';
import { DAPIClient } from './api/dapi.js';
import { buildInstantAssetLockProof } from './proof/index.js';
import { registerIdentity, topUpIdentity } from './platform/index.js';
import { privateKeyToWif, bytesToHex } from './utils/index.js';
import {
  createInitialState,
  setStep,
  setKeyPairs,
  setMode,
  setTargetIdentityId,
  setOneTimeKeyPair,
  setTopUpComplete,
  setUtxoDetected,
  setTransactionSigned,
  setTransactionBroadcast,
  setInstantLockReceived,
  setIdentityRegistered,
  setError,
  setDepositTimedOut,
  setNetwork,
  updateIdentityKey,
  addIdentityKey,
  removeIdentityKey,
  render,
  downloadKeyBackup,
  // DPNS state functions
  setModeDpnsFromIdentity,
  setDpnsIdentitySource,
  setDpnsExistingIdentity,
  addDpnsUsername,
  updateDpnsUsername,
  removeDpnsUsername,
  setDpnsChecking,
  setDpnsAvailability,
  acknowledgeDpnsContestedWarning,
  setDpnsRegistering,
  setDpnsRegistrationProgress,
  setDpnsResults,
  resetDpnsForMore,
  setDpnsBackToEntry,
  // New DPNS identity validation functions
  setDpnsIdentityFetching,
  setDpnsIdentityFetched,
  setDpnsIdentityFetchError,
  setDpnsKeyValidated,
  setDpnsKeyValidationError,
  clearDpnsKeyValidation,
} from './ui/index.js';
import {
  checkMultipleAvailability,
  registerMultipleNames,
  getIdentityPublicKeys,
} from './platform/dpns.js';
import {
  findMatchingKeyIndex,
  isSecurityLevelAllowedForDpns,
  isPurposeAllowedForDpns,
  getSecurityLevelName,
  getPurposeName,
} from './crypto/keys.js';
import type { KeyType, KeyPurpose, SecurityLevel } from './types.js';
import type { BridgeState } from './types.js';

// Global state
let state: BridgeState;
let insightClient: InsightClient;
let dapiClient: DAPIClient;

/**
 * Initialize the application
 */
function init() {
  // Get network from URL or default to testnet
  const urlParams = new URLSearchParams(window.location.search);
  const network = urlParams.get('network') === 'mainnet' ? 'mainnet' : 'testnet';

  // Initialize state
  state = createInitialState(network);
  insightClient = new InsightClient(getNetwork(network));
  dapiClient = new DAPIClient({ network });

  // Render UI
  const container = document.getElementById('app');
  if (container) {
    render(state, container);
    setupEventListeners(container);
  }
}

/**
 * Update state and re-render
 */
function updateState(newState: BridgeState) {
  state = newState;
  const container = document.getElementById('app');
  if (container) {
    // Save focus state before re-render
    const activeElement = document.activeElement as HTMLInputElement | null;
    const focusInfo = activeElement ? {
      id: activeElement.id,
      className: activeElement.className,
      dataIndex: activeElement.dataset?.index,
      selectionStart: activeElement.selectionStart,
      selectionEnd: activeElement.selectionEnd,
    } : null;

    render(state, container);
    setupEventListeners(container);

    // Restore focus after re-render
    if (focusInfo) {
      let elementToFocus: HTMLInputElement | null = null;

      // Try to find by ID first
      if (focusInfo.id) {
        elementToFocus = document.getElementById(focusInfo.id) as HTMLInputElement;
      }

      // For DPNS username inputs, find by data-index
      if (!elementToFocus && focusInfo.className?.includes('dpns-username-input') && focusInfo.dataIndex !== undefined) {
        elementToFocus = container.querySelector(
          `.dpns-username-input[data-index="${focusInfo.dataIndex}"]`
        ) as HTMLInputElement;
      }

      if (elementToFocus) {
        elementToFocus.focus();
        // Restore cursor position (only for text-like inputs)
        if (
          focusInfo.selectionStart !== null &&
          focusInfo.selectionEnd !== null &&
          typeof elementToFocus.setSelectionRange === 'function'
        ) {
          elementToFocus.setSelectionRange(focusInfo.selectionStart, focusInfo.selectionEnd);
        }
      }
    }
  }
}

/**
 * Setup event listeners
 */
function setupEventListeners(container: HTMLElement) {
  // Network selector buttons
  container.querySelectorAll('.network-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const network = (btn as HTMLElement).dataset.network as 'testnet' | 'mainnet';
      if (network && network !== state.network) {
        // Update state and reinitialize clients for new network
        updateState(setNetwork(state, network));
        insightClient = new InsightClient(getNetwork(network));
        dapiClient = new DAPIClient({ network });
      }
    });
  });

  // Mode selection buttons (init page)
  const modeCreateBtn = container.querySelector('#mode-create-btn');
  if (modeCreateBtn) {
    modeCreateBtn.addEventListener('click', () => {
      updateState(setMode(state, 'create'));
    });
  }

  const modeTopUpBtn = container.querySelector('#mode-topup-btn');
  if (modeTopUpBtn) {
    modeTopUpBtn.addEventListener('click', () => {
      updateState(setMode(state, 'topup'));
    });
  }

  // Back button (configure keys or enter identity -> init)
  const backBtn = container.querySelector('#back-btn');
  if (backBtn) {
    backBtn.addEventListener('click', () => {
      updateState(setStep(state, 'init'));
    });
  }

  // Identity ID input (for top-up mode)
  const identityInput = container.querySelector('#identity-id-input') as HTMLInputElement;
  if (identityInput) {
    identityInput.addEventListener('input', (e) => {
      const value = (e.target as HTMLInputElement).value.trim();
      updateState(setTargetIdentityId(state, value));
    });
  }

  // Continue top-up button
  const continueTopUpBtn = container.querySelector('#continue-topup-btn');
  if (continueTopUpBtn) {
    continueTopUpBtn.addEventListener('click', () => {
      if (validateIdentityId(state.targetIdentityId)) {
        startTopUp();
      } else {
        showValidationError('Please enter a valid identity ID (44 character Base58 string)');
      }
    });
  }

  // Continue button (configure keys -> start bridge)
  const continueBtn = container.querySelector('#continue-btn');
  if (continueBtn) {
    continueBtn.addEventListener('click', startBridge);
  }

  // Recheck deposit button
  const recheckBtn = container.querySelector('#recheck-deposit-btn');
  if (recheckBtn) {
    recheckBtn.addEventListener('click', recheckDeposit);
  }

  // Copy buttons
  container.querySelectorAll('.copy-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const text = (btn as HTMLElement).dataset.copy || '';
      navigator.clipboard.writeText(text);
      btn.textContent = 'Copied!';
      setTimeout(() => {
        btn.textContent = 'Copy';
      }, 2000);
    });
  });

  // Download keys button
  const downloadBtn = container.querySelector('#download-keys-btn');
  if (downloadBtn) {
    downloadBtn.addEventListener('click', () => {
      downloadKeyBackup(state);
    });
  }

  // Retry button
  const retryBtn = container.querySelector('#retry-btn');
  if (retryBtn) {
    retryBtn.addEventListener('click', () => {
      updateState(createInitialState(state.network));
    });
  }

  // Add key button
  const addKeyBtn = container.querySelector('#add-key-btn');
  if (addKeyBtn) {
    addKeyBtn.addEventListener('click', () => {
      updateState(addIdentityKey(state));
    });
  }

  // Remove key buttons
  container.querySelectorAll('.remove-key-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const keyId = parseInt((btn as HTMLElement).dataset.keyId || '0', 10);
      updateState(removeIdentityKey(state, keyId));
    });
  });

  // Key type selects
  container.querySelectorAll('.key-type-select').forEach((select) => {
    select.addEventListener('change', (e) => {
      const target = e.target as HTMLSelectElement;
      const keyId = parseInt(target.dataset.keyId || '0', 10);
      updateState(updateIdentityKey(state, keyId, { keyType: target.value as KeyType }));
    });
  });

  // Key purpose selects
  container.querySelectorAll('.key-purpose-select').forEach((select) => {
    select.addEventListener('change', (e) => {
      const target = e.target as HTMLSelectElement;
      const keyId = parseInt(target.dataset.keyId || '0', 10);
      updateState(updateIdentityKey(state, keyId, { purpose: target.value as KeyPurpose }));
    });
  });

  // Key security level selects
  container.querySelectorAll('.key-security-select').forEach((select) => {
    select.addEventListener('change', (e) => {
      const target = e.target as HTMLSelectElement;
      const keyId = parseInt(target.dataset.keyId || '0', 10);
      updateState(updateIdentityKey(state, keyId, { securityLevel: target.value as SecurityLevel }));
    });
  });

  // ============================================================================
  // DPNS Event Listeners
  // ============================================================================

  // DPNS mode button (init page)
  const modeDpnsBtn = container.querySelector('#mode-dpns-btn');
  if (modeDpnsBtn) {
    modeDpnsBtn.addEventListener('click', () => {
      updateState(setMode(state, 'dpns'));
    });
  }

  // DPNS from identity complete button
  const dpnsFromIdentityBtn = container.querySelector('#dpns-from-identity-btn');
  if (dpnsFromIdentityBtn) {
    dpnsFromIdentityBtn.addEventListener('click', () => {
      // Find a key with AUTHENTICATION purpose and CRITICAL or HIGH security level
      // Priority: CRITICAL > HIGH (keys 2 and 1 in default setup)
      const validKey = state.identityKeys.find(k =>
        k.purpose === 'AUTHENTICATION' &&
        (k.securityLevel === 'CRITICAL' || k.securityLevel === 'HIGH')
      );

      if (validKey) {
        const newState = setModeDpnsFromIdentity(state);
        updateState({
          ...newState,
          dpnsPrivateKeyWif: validKey.privateKeyWif,
          dpnsPublicKeyId: validKey.id,
        });
      } else {
        updateState(setError(
          state,
          new Error('No valid key for DPNS registration. You need an AUTHENTICATION key with CRITICAL or HIGH security level.')
        ));
      }
    });
  }

  // DPNS choose new identity button
  const dpnsChooseNewBtn = container.querySelector('#dpns-choose-new-btn');
  if (dpnsChooseNewBtn) {
    dpnsChooseNewBtn.addEventListener('click', () => {
      updateState(setDpnsIdentitySource(state, 'new'));
    });
  }

  // DPNS choose existing identity button
  const dpnsChooseExistingBtn = container.querySelector('#dpns-choose-existing-btn');
  if (dpnsChooseExistingBtn) {
    dpnsChooseExistingBtn.addEventListener('click', () => {
      updateState(setDpnsIdentitySource(state, 'existing'));
    });
  }

  // DPNS back button (various steps)
  const dpnsBackBtn = container.querySelector('#dpns-back-btn');
  if (dpnsBackBtn) {
    dpnsBackBtn.addEventListener('click', () => {
      // Navigate back based on current step
      switch (state.step) {
        case 'dpns_enter_identity':
          updateState(setStep(state, 'dpns_choose_identity'));
          break;
        case 'dpns_enter_usernames':
          if (state.dpnsFromIdentityCreation) {
            // Go back to complete screen
            updateState(setStep(state, 'complete'));
          } else if (state.dpnsIdentitySource === 'existing') {
            updateState(setStep(state, 'dpns_enter_identity'));
          } else {
            updateState(setStep(state, 'dpns_choose_identity'));
          }
          break;
        case 'dpns_review':
          updateState(setDpnsBackToEntry(state));
          break;
        default:
          updateState(setStep(state, 'init'));
      }
    });
  }

  // DPNS identity ID input - fetch on blur or paste
  const dpnsIdentityIdInput = container.querySelector('#dpns-identity-id-input');
  if (dpnsIdentityIdInput) {
    const fetchIdentity = async () => {
      const input = dpnsIdentityIdInput as HTMLInputElement;
      const identityId = input.value.trim();

      // Skip if empty or same as already fetched
      if (!identityId) {
        return;
      }

      // Skip if already fetching or already fetched this identity
      if (state.dpnsIdentityFetching || (state.targetIdentityId === identityId && state.dpnsIdentityKeys)) {
        return;
      }

      if (!validateIdentityId(identityId)) {
        updateState(setDpnsIdentityFetchError(state, 'Invalid identity ID format (expected 44 character Base58 string)'));
        return;
      }

      // Start fetching
      updateState(setDpnsIdentityFetching(state, identityId));

      try {
        const keys = await getIdentityPublicKeys(identityId, state.network);
        updateState(setDpnsIdentityFetched(state, keys));
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to fetch identity';
        updateState(setDpnsIdentityFetchError(state, message));
      }
    };

    dpnsIdentityIdInput.addEventListener('blur', fetchIdentity);
    dpnsIdentityIdInput.addEventListener('paste', () => {
      setTimeout(fetchIdentity, 50);
    });
  }

  // DPNS private key input - validate on blur or paste (waits for identity fetch if needed)
  const dpnsPrivateKeyInput = container.querySelector('#dpns-private-key-input');
  if (dpnsPrivateKeyInput) {
    const validatePrivateKey = async () => {
      const input = dpnsPrivateKeyInput as HTMLInputElement;
      const privateKeyWif = input.value.trim();

      // Clear previous validation if empty
      if (!privateKeyWif) {
        updateState(clearDpnsKeyValidation(state));
        return;
      }

      // Wait for identity fetch to complete if in progress
      const waitForIdentity = (): Promise<void> => {
        return new Promise((resolve) => {
          const check = () => {
            if (!state.dpnsIdentityFetching) {
              resolve();
            } else {
              setTimeout(check, 100);
            }
          };
          check();
        });
      };

      if (state.dpnsIdentityFetching) {
        await waitForIdentity();
      }

      // Check if identity was fetched successfully
      if (!state.dpnsIdentityKeys || state.dpnsIdentityKeys.length === 0) {
        if (state.dpnsIdentityFetchError) {
          // Identity fetch failed, don't validate key yet
          return;
        }
        updateState(setDpnsKeyValidationError(state, 'Please enter an identity ID first'));
        return;
      }

      // Find matching key
      const match = findMatchingKeyIndex(privateKeyWif, state.dpnsIdentityKeys, state.network);

      if (!match) {
        updateState(setDpnsKeyValidationError(state, 'This key does not match any key registered with this identity'));
        return;
      }

      // Check purpose (must be AUTHENTICATION)
      if (!isPurposeAllowedForDpns(match.purpose)) {
        const purposeName = getPurposeName(match.purpose);
        updateState(setDpnsKeyValidationError(
          state,
          `This key has ${purposeName} purpose. Please use an AUTHENTICATION key for DPNS registration.`
        ));
        return;
      }

      // Check security level (must be CRITICAL or HIGH)
      if (!isSecurityLevelAllowedForDpns(match.securityLevel)) {
        const levelName = getSecurityLevelName(match.securityLevel);
        updateState(setDpnsKeyValidationError(
          state,
          `This key has ${levelName} security level. Please use a CRITICAL or HIGH level key for DPNS registration.`
        ));
        return;
      }

      // Key is valid
      updateState(setDpnsKeyValidated(state, match.keyId, privateKeyWif));
    };

    dpnsPrivateKeyInput.addEventListener('blur', validatePrivateKey);
    dpnsPrivateKeyInput.addEventListener('paste', () => {
      // Small delay to let the paste complete before validating
      setTimeout(validatePrivateKey, 50);
    });
  }

  // DPNS identity continue button (only enabled when key is validated)
  const dpnsIdentityContinueBtn = container.querySelector('#dpns-identity-continue-btn');
  if (dpnsIdentityContinueBtn) {
    dpnsIdentityContinueBtn.addEventListener('click', () => {
      // Validation already done, just proceed if we have validated key
      if (state.dpnsValidatedKeyId !== undefined && state.targetIdentityId && state.dpnsPrivateKeyWif) {
        updateState(setDpnsExistingIdentity(
          state,
          state.targetIdentityId,
          state.dpnsPrivateKeyWif,
          state.dpnsValidatedKeyId
        ));
      }
    });
  }

  // DPNS username inputs
  container.querySelectorAll('.dpns-username-input').forEach((input) => {
    input.addEventListener('input', (e) => {
      const target = e.target as HTMLInputElement;
      const index = parseInt(target.dataset.index || '0', 10);
      updateState(updateDpnsUsername(state, index, target.value));
    });
  });

  // DPNS add username button
  const addDpnsUsernameBtn = container.querySelector('#add-dpns-username-btn');
  if (addDpnsUsernameBtn) {
    addDpnsUsernameBtn.addEventListener('click', () => {
      updateState(addDpnsUsername(state));
    });
  }

  // DPNS remove username buttons
  container.querySelectorAll('.remove-dpns-username-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const index = parseInt((btn as HTMLElement).dataset.index || '0', 10);
      updateState(removeDpnsUsername(state, index));
    });
  });

  // DPNS check availability button
  const checkAvailabilityBtn = container.querySelector('#check-availability-btn');
  if (checkAvailabilityBtn) {
    checkAvailabilityBtn.addEventListener('click', startDpnsCheck);
  }

  // DPNS add non-contested button (in review warning)
  const addNoncontestedBtn = container.querySelector('#add-noncontested-btn');
  if (addNoncontestedBtn) {
    addNoncontestedBtn.addEventListener('click', () => {
      // Go back to username entry to add more
      updateState(setDpnsBackToEntry(addDpnsUsername(state)));
    });
  }

  // DPNS contested warning checkbox
  const dpnsContestedCheckbox = container.querySelector('#dpns-contested-checkbox') as HTMLInputElement;
  if (dpnsContestedCheckbox) {
    dpnsContestedCheckbox.addEventListener('change', () => {
      if (dpnsContestedCheckbox.checked) {
        updateState(acknowledgeDpnsContestedWarning(state));
      }
    });
  }

  // DPNS register button
  const registerDpnsBtn = container.querySelector('#register-dpns-btn');
  if (registerDpnsBtn) {
    registerDpnsBtn.addEventListener('click', startDpnsRegistration);
  }

  // DPNS register more button
  const dpnsRegisterMoreBtn = container.querySelector('#dpns-register-more-btn');
  if (dpnsRegisterMoreBtn) {
    dpnsRegisterMoreBtn.addEventListener('click', () => {
      updateState(resetDpnsForMore(state));
    });
  }
}

/**
 * Validate identity ID format (Base58, ~44 characters)
 */
function validateIdentityId(id?: string): boolean {
  if (!id) return false;
  // Dash identity IDs are Base58 encoded, typically 43-44 characters
  return /^[1-9A-HJ-NP-Za-km-z]{43,44}$/.test(id);
}

/**
 * Show validation error message in the UI
 */
function showValidationError(message: string): void {
  const validationMsg = document.getElementById('validation-msg');
  if (validationMsg) {
    validationMsg.textContent = message;
    validationMsg.classList.remove('hidden');
  }
}

/**
 * Start the top-up process
 */
async function startTopUp() {
  try {
    const network = getNetwork(state.network);

    // Step 1: Generate random one-time key pair (NOT HD-derived)
    updateState(setStep(state, 'generating_keys'));

    const assetLockKeyPair = generateKeyPair();
    const depositAddress = publicKeyToAddress(assetLockKeyPair.publicKey, network);

    const stateWithKeys = setOneTimeKeyPair(state, assetLockKeyPair, depositAddress);
    updateState(stateWithKeys);

    // Auto-download key backup immediately for safety
    // CRITICAL: User must have this to recover funds if something goes wrong
    downloadKeyBackup(stateWithKeys);

    // Step 2: Wait for deposit
    updateState(setStep(stateWithKeys, 'detecting_deposit'));

    const minAmount = 300000; // 0.003 DASH minimum
    const depositResult = await insightClient.waitForUtxo(
      depositAddress,
      minAmount,
      120000, // 2 minutes before showing recheck button
      3000    // poll every 3 seconds
    );

    // Handle timeout - show recheck button with any detected amount
    if (!depositResult.utxo) {
      updateState(setDepositTimedOut(state, true, depositResult.totalAmount));
      return;
    }

    const utxo = depositResult.utxo;

    updateState(setUtxoDetected(state, utxo));

    // Step 3: Build transaction
    updateState(setStep(state, 'building_transaction'));

    const tx = createAssetLockTransaction(
      utxo,
      assetLockKeyPair.publicKey,
      BigInt(network.minFee)
    );

    // Step 4: Sign transaction
    updateState(setStep(state, 'signing_transaction'));

    const signedTx = await signTransaction(
      tx,
      [utxo],
      assetLockKeyPair.privateKey,
      assetLockKeyPair.publicKey
    );

    const signedTxBytes = serializeTransaction(signedTx);
    const signedTxHex = bytesToHex(signedTxBytes);

    updateState(setTransactionSigned(state, signedTxHex));

    // Step 5: Broadcast transaction
    const txid = await insightClient.broadcastTransaction(signedTxHex);

    updateState(setTransactionBroadcast(state, txid));

    // Step 6: Wait for InstantSend lock
    updateState(setStep(state, 'waiting_islock'));

    console.log('Waiting for InstantSend lock...');
    const islockBytes = await dapiClient.waitForInstantSendLock(txid, 60000);
    console.log('InstantSend lock received:', islockBytes.length, 'bytes');

    const assetLockProof = buildInstantAssetLockProof(
      signedTxBytes,
      islockBytes,
      0
    );

    updateState(setInstantLockReceived(state, islockBytes, assetLockProof));

    // Step 7: Top up identity (different from create)
    updateState(setStep(state, 'topping_up'));

    const assetLockPrivateKeyWif = privateKeyToWif(
      assetLockKeyPair.privateKey,
      network
    );

    await topUpIdentity(
      state.targetIdentityId!,
      assetLockProof,
      assetLockPrivateKeyWif,
      state.network
    );

    updateState(setTopUpComplete(state));

  } catch (error) {
    console.error('Top-up error:', error);
    updateState(setError(state, error instanceof Error ? error : new Error(String(error))));
  }
}

/**
 * Start the bridge process (identity creation)
 */
async function startBridge() {
  try {
    const network = getNetwork(state.network);

    // Ensure mnemonic exists
    if (!state.mnemonic) {
      throw new Error('No mnemonic available for HD derivation');
    }

    // Step 1: Derive asset lock key from mnemonic (identity keys are pre-configured in state)
    updateState(setStep(state, 'generating_keys'));

    const { privateKey, publicKey } = deriveAssetLockKeyPair(state.mnemonic, state.network);
    const assetLockKeyPair = { privateKey, publicKey };
    const depositAddress = publicKeyToAddress(assetLockKeyPair.publicKey, network);

    updateState(
      setKeyPairs(state, assetLockKeyPair, depositAddress)
    );

    // Auto-download key backup immediately for safety
    // This ensures users can recover funds if they reload the page
    downloadKeyBackup(state);

    // Step 2: Wait for deposit
    updateState(setStep(state, 'detecting_deposit'));

    const minAmount = 300000; // 0.003 DASH minimum
    const depositResult = await insightClient.waitForUtxo(
      depositAddress,
      minAmount,
      120000, // 2 minutes before showing recheck button
      3000    // poll every 3 seconds
    );

    // Handle timeout - show recheck button with any detected amount
    if (!depositResult.utxo) {
      updateState(setDepositTimedOut(state, true, depositResult.totalAmount));
      return;
    }

    const utxo = depositResult.utxo;

    updateState(setUtxoDetected(state, utxo));

    // Step 3: Build transaction
    updateState(setStep(state, 'building_transaction'));

    const tx = createAssetLockTransaction(
      utxo,
      assetLockKeyPair.publicKey,
      BigInt(network.minFee)
    );

    // Step 4: Sign transaction
    updateState(setStep(state, 'signing_transaction'));

    const signedTx = await signTransaction(
      tx,
      [utxo],
      assetLockKeyPair.privateKey,
      assetLockKeyPair.publicKey
    );

    const signedTxBytes = serializeTransaction(signedTx);
    const signedTxHex = bytesToHex(signedTxBytes);

    updateState(setTransactionSigned(state, signedTxHex));

    // Step 5: Broadcast transaction
    const txid = await insightClient.broadcastTransaction(signedTxHex);

    updateState(setTransactionBroadcast(state, txid));

    // Step 6: Wait for InstantSend lock
    updateState(setStep(state, 'waiting_islock'));

    console.log('Waiting for InstantSend lock...');
    const islockBytes = await dapiClient.waitForInstantSendLock(txid, 60000);
    console.log('InstantSend lock received:', islockBytes.length, 'bytes');

    const assetLockProof = buildInstantAssetLockProof(
      signedTxBytes,
      islockBytes,
      0
    );

    updateState(setInstantLockReceived(state, islockBytes, assetLockProof));

    // Step 7: Register identity
    updateState(setStep(state, 'registering_identity'));

    const assetLockPrivateKeyWif = privateKeyToWif(
      assetLockKeyPair.privateKey,
      network
    );

    const result = await registerIdentity(
      assetLockProof,
      assetLockPrivateKeyWif,
      state.identityKeys,
      state.network
    );

    updateState(setIdentityRegistered(state, result.identityId));

  } catch (error) {
    console.error('Bridge error:', error);
    updateState(setError(state, error instanceof Error ? error : new Error(String(error))));
  }
}

/**
 * Recheck for deposit (called when user clicks "Check Again" after timeout)
 */
async function recheckDeposit() {
  if (!state.depositAddress) {
    console.error('No deposit address available');
    return;
  }

  // Reset timeout state and start polling again
  updateState(setDepositTimedOut(state, false, 0));

  const minAmount = 300000; // 0.003 DASH minimum
  const depositResult = await insightClient.waitForUtxo(
    state.depositAddress,
    minAmount,
    120000, // 2 minutes before showing recheck button
    3000    // poll every 3 seconds
  );

  // Handle timeout - show recheck button again with any detected amount
  if (!depositResult.utxo) {
    updateState(setDepositTimedOut(state, true, depositResult.totalAmount));
    return;
  }

  const utxo = depositResult.utxo;

  // Continue with the rest of the bridge process
  try {
    const network = getNetwork(state.network);
    const assetLockKeyPair = state.assetLockKeyPair!;

    updateState(setUtxoDetected(state, utxo));

    // Step 3: Build transaction
    updateState(setStep(state, 'building_transaction'));

    const tx = createAssetLockTransaction(
      utxo,
      assetLockKeyPair.publicKey,
      BigInt(network.minFee)
    );

    // Step 4: Sign transaction
    updateState(setStep(state, 'signing_transaction'));

    const signedTx = await signTransaction(
      tx,
      [utxo],
      assetLockKeyPair.privateKey,
      assetLockKeyPair.publicKey
    );

    const signedTxBytes = serializeTransaction(signedTx);
    const signedTxHex = bytesToHex(signedTxBytes);

    updateState(setTransactionSigned(state, signedTxHex));

    // Step 5: Broadcast transaction
    const txid = await insightClient.broadcastTransaction(signedTxHex);

    updateState(setTransactionBroadcast(state, txid));

    // Step 6: Wait for InstantSend lock
    updateState(setStep(state, 'waiting_islock'));

    console.log('Waiting for InstantSend lock...');
    const islockBytes = await dapiClient.waitForInstantSendLock(txid, 60000);
    console.log('InstantSend lock received:', islockBytes.length, 'bytes');

    const assetLockProof = buildInstantAssetLockProof(
      signedTxBytes,
      islockBytes,
      0
    );

    updateState(setInstantLockReceived(state, islockBytes, assetLockProof));

    // Step 7: Register identity
    updateState(setStep(state, 'registering_identity'));

    const assetLockPrivateKeyWif = privateKeyToWif(
      assetLockKeyPair.privateKey,
      network
    );

    const result = await registerIdentity(
      assetLockProof,
      assetLockPrivateKeyWif,
      state.identityKeys,
      state.network
    );

    updateState(setIdentityRegistered(state, result.identityId));

  } catch (error) {
    console.error('Bridge error:', error);
    updateState(setError(state, error instanceof Error ? error : new Error(String(error))));
  }
}

// ============================================================================
// DPNS Functions
// ============================================================================

/**
 * Start DPNS availability check
 */
async function startDpnsCheck() {
  try {
    const usernames = state.dpnsUsernames || [];
    const validUsernames = usernames.filter((u) => u.isValid);

    if (validUsernames.length === 0) {
      return;
    }

    // Transition to checking state
    updateState(setDpnsChecking(state));

    // Check availability for all valid usernames
    const results = await checkMultipleAvailability(validUsernames, state.network);

    // Update state with results
    updateState(setDpnsAvailability(state, results));

  } catch (error) {
    console.error('DPNS check error:', error);
    updateState(setError(state, error instanceof Error ? error : new Error(String(error))));
  }
}

/**
 * Start DPNS registration
 */
async function startDpnsRegistration() {
  try {
    const usernames = state.dpnsUsernames || [];
    const availableUsernames = usernames.filter((u) => u.isValid && u.isAvailable);

    if (availableUsernames.length === 0) {
      return;
    }

    // Get identity ID and private key
    const identityId = state.identityId || state.targetIdentityId;
    const privateKeyWif = state.dpnsPrivateKeyWif;
    const publicKeyId = state.dpnsPublicKeyId ?? 0;

    if (!identityId) {
      throw new Error('No identity ID available for DPNS registration');
    }

    if (!privateKeyWif) {
      throw new Error('No private key available for DPNS registration');
    }

    // Transition to registering state
    updateState(setDpnsRegistering(state));

    // Register all available usernames
    const results = await registerMultipleNames(
      availableUsernames,
      identityId,
      publicKeyId,
      privateKeyWif,
      state.network,
      (current, total, label) => {
        console.log(`Registering ${label} (${current}/${total})...`);
        updateState(setDpnsRegistrationProgress(state, current - 1));
      }
    );

    // Update state with results
    updateState(setDpnsResults(state, results));

  } catch (error) {
    console.error('DPNS registration error:', error);
    updateState(setError(state, error instanceof Error ? error : new Error(String(error))));
  }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
