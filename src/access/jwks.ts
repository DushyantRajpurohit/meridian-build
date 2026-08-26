import { importJWK, type CryptoKey, type JWK } from 'jose'

/**
 * R18 — the team JWKS, fetched and cached by us rather than by a library, so the two
 * questions the requirement asks have answers in code rather than in prose.
 *
 * TTL is 15 minutes. That is the compromise: Cloudflare publishes several signing keys at
 * once and rotates them roughly every six weeks, so a short TTL buys very little freshness
 * for a lot of egress, while a long one lengthens the window in which a newly-rotated key is
 * unknown to us.
 *
 * The TTL is not what makes rotation safe, though. `kid` is: a token signed by a key we have
 * never seen forces an immediate refetch regardless of how fresh the cache is. So a rotation
 * costs one extra fetch rather than up to 15 minutes of 403s.
 *
 * That forced path is floored at one refetch per 10 seconds, because otherwise a stream of
 * requests carrying random kids becomes a request amplifier pointed at Cloudflare. Ten
 * seconds is the whole cost of the protection: it is the longest a genuinely rotated key can
 * be unknown to us. A minute was the first number here and it was wrong — it priced an
 * availability risk that is real against an amplification risk that a much smaller floor
 * already closes, since one fetch per 10s is nothing however many unknown kids arrive.
 *
 * In practice even that is rarely paid: Cloudflare publishes a new signing key alongside the
 * old one before it starts signing with it, so the new kid is usually already in a cache
 * fetched under the ordinary TTL.
 *
 * If the fetch fails we keep serving the stale set for up to an hour. That is not fail-open:
 * every signature is still checked against a key Cloudflare published. It only means a blip
 * on the certs endpoint does not lock the staff out of their own console.
 */

export interface JwksCacheOptions {
  /** https://<team>.cloudflareaccess.com/cdn-cgi/access/certs */
  certsUrl: string
  ttlMs?: number
  /** Floor between forced refreshes triggered by an unknown kid. */
  minRefreshIntervalMs?: number
  /** How long a failing endpoint may be papered over with the previous key set. */
  maxStaleMs?: number
  fetchImpl?: typeof fetch
}

export class JwksFetchError extends Error {
  constructor(message: string, cause?: unknown) {
    super(message, { cause })
    this.name = 'JwksFetchError'
  }
}

interface CacheEntry {
  keys: Map<string, CryptoKey | Uint8Array>
  fetchedAt: number
}

export class JwksCache {
  private readonly certsUrl: string
  private readonly ttlMs: number
  private readonly minRefreshIntervalMs: number
  private readonly maxStaleMs: number
  private readonly fetchImpl: typeof fetch

  private entry: CacheEntry | null = null
  private inflight: Promise<CacheEntry> | null = null
  private lastAttemptAt = 0

  constructor(options: JwksCacheOptions) {
    this.certsUrl = options.certsUrl
    this.ttlMs = options.ttlMs ?? 15 * 60_000
    this.minRefreshIntervalMs = options.minRefreshIntervalMs ?? 10_000
    this.maxStaleMs = options.maxStaleMs ?? 60 * 60_000
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch
  }

  /** Resolve a `kid` to a verification key, refetching once if the kid is unknown. */
  async getKey(kid: string): Promise<CryptoKey | Uint8Array> {
    const fresh = this.entry !== null && Date.now() - this.entry.fetchedAt < this.ttlMs
    let entry = fresh ? this.entry! : await this.refresh()

    if (!entry.keys.has(kid) && this.mayForceRefresh()) {
      entry = await this.refresh()
    }

    const key = entry.keys.get(kid)
    if (key === undefined) {
      throw new JwksFetchError(`no signing key published for kid ${kid}`)
    }
    return key
  }

  private mayForceRefresh(): boolean {
    return Date.now() - this.lastAttemptAt >= this.minRefreshIntervalMs
  }

  private async refresh(): Promise<CacheEntry> {
    // Collapse concurrent misses onto one request. A cold start that takes twenty requests
    // at once should still only ask Cloudflare once.
    this.inflight ??= this.fetchKeys().finally(() => {
      this.inflight = null
    })

    try {
      this.entry = await this.inflight
      return this.entry
    } catch (error) {
      const stale = this.entry
      if (stale !== null && Date.now() - stale.fetchedAt < this.maxStaleMs) {
        return stale
      }
      throw error
    }
  }

  private async fetchKeys(): Promise<CacheEntry> {
    this.lastAttemptAt = Date.now()

    let response: Response
    try {
      response = await this.fetchImpl(this.certsUrl, {
        headers: { accept: 'application/json' },
        signal: AbortSignal.timeout(5_000),
      })
    } catch (error) {
      throw new JwksFetchError(`could not reach ${this.certsUrl}`, error)
    }

    if (!response.ok) {
      throw new JwksFetchError(`${this.certsUrl} returned ${response.status}`)
    }

    const body = (await response.json()) as { keys?: JWK[] }
    if (!Array.isArray(body.keys) || body.keys.length === 0) {
      throw new JwksFetchError(`${this.certsUrl} published no keys`)
    }

    const keys = new Map<string, CryptoKey | Uint8Array>()
    for (const jwk of body.keys) {
      // Access signs with RS256. Importing anything else would widen the algorithm surface
      // for no reason, and `alg` confusion is exactly the class of bug this file exists for.
      if (typeof jwk.kid !== 'string' || (jwk.alg !== undefined && jwk.alg !== 'RS256')) continue
      keys.set(jwk.kid, await importJWK(jwk, 'RS256'))
    }

    if (keys.size === 0) {
      throw new JwksFetchError(`${this.certsUrl} published no usable RS256 keys`)
    }

    return { keys, fetchedAt: Date.now() }
  }

  /** Test and triage helper: what is cached, and how old is it. */
  stats(): { kids: string[]; ageMs: number | null } {
    return {
      kids: this.entry === null ? [] : [...this.entry.keys.keys()],
      ageMs: this.entry === null ? null : Date.now() - this.entry.fetchedAt,
    }
  }
}
