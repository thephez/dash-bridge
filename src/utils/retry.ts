/**
 * Retry utility with exponential backoff for network resilience
 */

export interface RetryOptions {
  /** Maximum number of attempts (default: 3) */
  maxAttempts?: number;
  /** Base delay in ms between retries (default: 1000) */
  baseDelayMs?: number;
  /** Maximum delay cap in ms (default: 10000) */
  maxDelayMs?: number;
  /** Custom function to determine if error is retryable */
  shouldRetry?: (error: unknown) => boolean;
  /** Callback invoked on each retry attempt */
  onRetry?: (attempt: number, maxAttempts: number, error: unknown) => void;
}

/**
 * Check if an error is a retryable network/transient error
 */
export function isRetryableError(error: unknown): boolean {
  // Network errors from fetch (TypeError on network failure)
  if (error instanceof TypeError) {
    const message = error.message.toLowerCase();
    if (
      message.includes('network') ||
      message.includes('fetch') ||
      message.includes('failed to fetch') ||
      message.includes('load failed') ||
      message.includes('networkerror')
    ) {
      return true;
    }
  }

  // Check for common network error patterns
  if (error instanceof Error) {
    const message = error.message.toLowerCase();

    // Network connectivity errors
    if (
      message.includes('err_internet_disconnected') ||
      message.includes('err_network') ||
      message.includes('econnreset') ||
      message.includes('econnrefused') ||
      message.includes('etimedout') ||
      message.includes('enotfound') ||
      message.includes('network request failed') ||
      message.includes('network error') ||
      message.includes('connection') ||
      message.includes('timeout')
    ) {
      return true;
    }

    // HTTP status codes that are retryable (from error messages)
    if (
      message.includes('500') ||
      message.includes('502') ||
      message.includes('503') ||
      message.includes('504') ||
      message.includes('429') || // Rate limit
      message.includes('internal server error') ||
      message.includes('bad gateway') ||
      message.includes('service unavailable') ||
      message.includes('gateway timeout')
    ) {
      return true;
    }
  }

  // DOMException for aborted requests (could be network-related)
  if (error instanceof DOMException && error.name === 'AbortError') {
    return true;
  }

  return false;
}

/**
 * Calculate delay with exponential backoff and jitter
 */
function calculateDelay(attempt: number, baseDelayMs: number, maxDelayMs: number): number {
  // Exponential backoff: baseDelay * 2^attempt
  const exponentialDelay = baseDelayMs * Math.pow(2, attempt);

  // Cap at maxDelay
  const cappedDelay = Math.min(exponentialDelay, maxDelayMs);

  // Add jitter: random value between 0 and 50% of the delay
  const jitter = Math.random() * cappedDelay * 0.5;

  return Math.floor(cappedDelay + jitter);
}

/**
 * Execute a function with retry logic
 *
 * @param fn - Async function to execute
 * @param options - Retry configuration options
 * @returns The result of the function
 * @throws The last error if all retries fail
 */
export async function withRetry<T>(
  fn: () => Promise<T>,
  options: RetryOptions = {}
): Promise<T> {
  const {
    maxAttempts = 3,
    baseDelayMs = 1000,
    maxDelayMs = 10000,
    shouldRetry = isRetryableError,
    onRetry,
  } = options;

  let lastError: unknown;

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;

      // Check if we should retry
      const isLastAttempt = attempt === maxAttempts - 1;
      if (isLastAttempt || !shouldRetry(error)) {
        throw error;
      }

      // Calculate delay for next attempt
      const delay = calculateDelay(attempt, baseDelayMs, maxDelayMs);

      // Notify via callback
      if (onRetry) {
        onRetry(attempt + 1, maxAttempts, error);
      }

      // Log retry attempt
      console.warn(
        `Retry ${attempt + 1}/${maxAttempts} after ${delay}ms:`,
        error instanceof Error ? error.message : error
      );

      // Wait before next attempt
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }

  // Should not reach here, but just in case
  throw lastError;
}

/**
 * Create a retry wrapper with pre-configured options
 */
export function createRetryWrapper(defaultOptions: RetryOptions) {
  return <T>(fn: () => Promise<T>, options?: RetryOptions): Promise<T> => {
    return withRetry(fn, { ...defaultOptions, ...options });
  };
}
