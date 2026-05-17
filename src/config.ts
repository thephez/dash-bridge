export interface NetworkConfig {
  type: 'testnet' | 'mainnet' | 'devnet';
  name: string;
  insightApiUrl: string;
  addressPrefix: number;
  wifPrefix: number;
  minFee: number;
  dustThreshold: number;
  platformHrp: string;
  faucetBaseUrl?: string;
  dapiAddresses?: string[];
  rpcUrl?: string;
}

export const TESTNET: NetworkConfig = {
  type: 'testnet',
  name: 'testnet',
  insightApiUrl: 'https://insight.testnet.networks.dash.org/insight-api',
  addressPrefix: 140,
  wifPrefix: 239,
  minFee: 1000,
  dustThreshold: 546,
  platformHrp: 'tdash',
  faucetBaseUrl: 'https://faucet.thepasta.org',
  rpcUrl: 'https://trpc.digitalcash.dev',
};

export const MAINNET: NetworkConfig = {
  type: 'mainnet',
  name: 'mainnet',
  insightApiUrl: 'https://insight.dash.org/insight-api',
  addressPrefix: 76,
  wifPrefix: 204,
  minFee: 1000,
  dustThreshold: 546,
  platformHrp: 'dash',
  rpcUrl: 'https://rpc.digitalcash.dev',
};

export const DEVNET_TADI: NetworkConfig = {
  type: 'devnet',
  name: 'devnet-tadi',
  insightApiUrl: 'https://insight.devnet-tadi.networks.dash.org/insight-api',
  addressPrefix: 140,
  wifPrefix: 239,
  minFee: 1000,
  dustThreshold: 546,
  platformHrp: 'tdash',
  dapiAddresses: [
    'https://35.89.28.18:1443',
    'https://34.217.21.126:1443',
    'https://34.219.89.114:1443',
    'https://44.249.83.233:1443',
    'https://54.188.228.213:1443',
    'https://54.244.210.104:1443',
    'https://34.219.127.187:1443',
    'https://18.237.1.251:1443',
    'https://35.89.185.80:1443',
    'https://34.219.40.199:1443',
  ],
  faucetBaseUrl: 'https://faucet.devnet-tadi.networks.dash.org',
};

const NETWORK_REGISTRY = new Map<string, NetworkConfig>([
  ['testnet', TESTNET],
  ['mainnet', MAINNET],
  ['devnet-tadi', DEVNET_TADI],
]);

const CUSTOM_DEVNETS_KEY = 'bridge-custom-devnets';

function loadCustomDevnets(): NetworkConfig[] {
  try {
    const stored = localStorage.getItem(CUSTOM_DEVNETS_KEY);
    if (!stored) return [];
    const parsed = JSON.parse(stored);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (c): c is NetworkConfig =>
        c &&
        typeof c.name === 'string' &&
        c.type === 'devnet' &&
        typeof c.insightApiUrl === 'string' &&
        typeof c.addressPrefix === 'number' &&
        typeof c.wifPrefix === 'number' &&
        typeof c.platformHrp === 'string'
    );
  } catch {
    return [];
  }
}

export function saveCustomDevnet(config: NetworkConfig): void {
  const customs = loadCustomDevnets().filter((c) => c.name !== config.name);
  customs.push(config);
  localStorage.setItem(CUSTOM_DEVNETS_KEY, JSON.stringify(customs));
  NETWORK_REGISTRY.set(config.name, config);
}

export function removeCustomDevnet(name: string): void {
  const customs = loadCustomDevnets().filter((c) => c.name !== name);
  localStorage.setItem(CUSTOM_DEVNETS_KEY, JSON.stringify(customs));
  NETWORK_REGISTRY.delete(name);
}

export function createCustomDevnetConfig(params: {
  name: string;
  insightApiUrl: string;
  dapiAddresses: string[];
  rpcUrl?: string;
  faucetBaseUrl?: string;
}): NetworkConfig {
  return {
    type: 'devnet',
    name: params.name,
    insightApiUrl: params.insightApiUrl,
    addressPrefix: 140,
    wifPrefix: 239,
    minFee: 1000,
    dustThreshold: 546,
    platformHrp: 'tdash',
    dapiAddresses: params.dapiAddresses,
    rpcUrl: params.rpcUrl,
    faucetBaseUrl: params.faucetBaseUrl,
  };
}

export function initNetworkRegistry(): void {
  for (const config of loadCustomDevnets()) {
    NETWORK_REGISTRY.set(config.name, config);
  }
}

export function getNetwork(name: string): NetworkConfig {
  const config = NETWORK_REGISTRY.get(name);
  if (config) return config;
  console.warn(`Unknown network "${name}", falling back to testnet`);
  return TESTNET;
}

export function getAvailableNetworks(): NetworkConfig[] {
  return Array.from(NETWORK_REGISTRY.values());
}

export function getDerivationNetwork(name: string): 'testnet' | 'mainnet' {
  return name === 'mainnet' ? 'mainnet' : 'testnet';
}
