/**
 * The key-value store, described structurally rather than as `KVNamespace`.
 *
 * A real KV binding satisfies this as it stands, and so does a Map behind two async methods.
 * That is what lets the rate limiter be unit-tested without the Workers runtime, and what
 * lets scripts/local-edge.ts run the very same code the deployment runs rather than a
 * lookalike that drifts out of step with it.
 */
export interface KeyValueStore {
  get(key: string): Promise<string | null>
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>
}
