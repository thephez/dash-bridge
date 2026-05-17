/* eslint-disable @typescript-eslint/no-explicit-any */

import DAPIClientModule from '@dashevo/dapi-client';
import dashcoreLib from '@dashevo/dashcore-lib';

interface BloomFilterStatic {
  create(elements: number, falsePositiveRate: number, nTweak: number, nFlags: number): {
    vData: number[];
    nHashFuncs: number;
    nTweak: number;
    nFlags: number;
    insert(data: Uint8Array | Buffer): void;
  };
  BLOOM_UPDATE_ALL: number;
}

interface InstantLockStatic {
  fromBuffer(buffer: Buffer): { txid: string };
}

const DAPIClientClass = (DAPIClientModule as any).default || DAPIClientModule;
const BloomFilter = (dashcoreLib as any).BloomFilter as BloomFilterStatic;
const InstantLock = (dashcoreLib as any).InstantLock as InstantLockStatic;

export interface DAPISubscriptionConfig {
  network: string;
  dapiAddresses?: string[];
}

export class DAPISubscriptionClient {
  readonly network: string;
  private readonly dapiAddresses?: string[];
  private dapiClient: any = null;

  constructor(config: DAPISubscriptionConfig) {
    this.network = config.network;
    this.dapiAddresses = config.dapiAddresses;
  }

  private getClient(): any {
    if (!this.dapiClient) {
      const options: any = {
        timeout: 30000,
        retries: 3,
      };

      if (this.dapiAddresses?.length) {
        options.dapiAddresses = this.dapiAddresses;
      } else {
        options.network = this.network === 'mainnet' ? 'mainnet' : 'testnet';
      }

      this.dapiClient = new DAPIClientClass(options);
    }
    return this.dapiClient;
  }

  private createBloomFilter(
    pubKeyHash: Uint8Array,
    outpoint: { txid: string; vout: number }
  ): { vData: Uint8Array; nHashFuncs: number; nTweak: number; nFlags: number } {
    const nTweak = Math.floor(Math.random() * 0xffffffff);
    const filter = BloomFilter.create(3, 0.01, nTweak, BloomFilter.BLOOM_UPDATE_ALL);

    filter.insert(Buffer.from(pubKeyHash));

    const scriptPubKey = Buffer.concat([
      Buffer.from([0x76, 0xa9, 0x14]),
      Buffer.from(pubKeyHash),
      Buffer.from([0x88, 0xac]),
    ]);
    filter.insert(scriptPubKey);

    const txidBytes = Buffer.from(outpoint.txid, 'hex').reverse();
    const voutBytes = Buffer.alloc(4);
    voutBytes.writeUInt32LE(outpoint.vout, 0);
    filter.insert(Buffer.concat([txidBytes, voutBytes]));

    return {
      vData: new Uint8Array(filter.vData),
      nHashFuncs: filter.nHashFuncs,
      nTweak: filter.nTweak,
      nFlags: filter.nFlags,
    };
  }

  private parseInstantLockTxid(islockBytes: Uint8Array): string | null {
    try {
      return InstantLock.fromBuffer(Buffer.from(islockBytes)).txid;
    } catch {
      return null;
    }
  }

  private async getBestBlockHeight(): Promise<number> {
    const client = this.getClient();
    return await client.core.getBestBlockHeight();
  }

  async waitForInstantSendLock(
    txid: string,
    pubKeyHash: Uint8Array,
    outpoint: { txid: string; vout: number },
    timeoutMs: number = 60000,
    onProgress?: (message: string) => void
  ): Promise<Uint8Array> {
    const client = this.getClient();

    onProgress?.('Creating bloom filter...');
    const bloomFilter = this.createBloomFilter(pubKeyHash, outpoint);

    onProgress?.('Getting current block height...');
    const currentHeight = await this.getBestBlockHeight();
    const fromBlockHeight = Math.max(1, currentHeight - 10);

    onProgress?.(`Subscribing from block ${fromBlockHeight}...`);

    return new Promise<Uint8Array>((resolve, reject) => {
      let stream: any = null;
      let timeoutId: ReturnType<typeof setTimeout> | null = null;
      let resolved = false;

      const cleanup = () => {
        if (timeoutId) {
          clearTimeout(timeoutId);
          timeoutId = null;
        }
        if (stream) {
          try { stream.cancel(); } catch { /* ignore */ }
          stream = null;
        }
      };

      timeoutId = setTimeout(() => {
        if (!resolved) {
          resolved = true;
          cleanup();
          reject(new Error(`Timeout waiting for InstantSend lock for ${txid} after ${timeoutMs}ms`));
        }
      }, timeoutMs);

      (async () => {
        try {
          stream = await client.core.subscribeToTransactionsWithProofs(
            bloomFilter,
            { fromBlockHeight, count: 0 }
          );

          onProgress?.('Listening for InstantSend lock...');

          stream.on('data', (response: unknown) => {
            if (resolved) return;

            try {
              const typedResponse = response as any;
              const islockMessages = typedResponse.getInstantSendLockMessages?.();

              if (islockMessages) {
                const messages = islockMessages.getMessagesList_asU8?.() || islockMessages.getMessagesList?.();
                if (messages && messages.length > 0) {
                  for (const msgBytes of messages) {
                    const bytes = msgBytes instanceof Uint8Array ? msgBytes : new Uint8Array(msgBytes);
                    const islockTxid = this.parseInstantLockTxid(bytes);

                    if (islockTxid === txid) {
                      onProgress?.('InstantSend lock received!');
                      resolved = true;
                      cleanup();
                      resolve(bytes);
                      return;
                    }
                  }
                }
              }
            } catch (error) {
              console.warn('Error processing stream data:', error);
            }
          });

          stream.on('error', (error: Error) => {
            if (resolved) return;
            resolved = true;
            cleanup();
            reject(error);
          });

          stream.on('end', () => {
            if (!resolved) {
              resolved = true;
              cleanup();
              reject(new Error(`Stream ended before receiving InstantSend lock for ${txid}`));
            }
          });
        } catch (error) {
          if (!resolved) {
            resolved = true;
            cleanup();
            reject(error);
          }
        }
      })();
    });
  }

  async disconnect(): Promise<void> {
    if (this.dapiClient) {
      try { await this.dapiClient.disconnect(); } catch { /* ignore */ }
      this.dapiClient = null;
    }
  }
}
