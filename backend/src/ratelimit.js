'use strict';
/**
 * Token-bucket rate limiting.
 *
 * Protects three distinct things:
 *   1. Prekey exhaustion. Without a limit, anyone can drain a victim's
 *      one-time prekeys by repeatedly fetching their bundle, forcing every
 *      subsequent session down to the weaker three-DH variant. This is a real
 *      cryptographic downgrade, not just a resource issue.
 *   2. Credential stuffing against /auth/login.
 *   3. Queue flooding against a recipient's offline storage.
 */

const BUCKETS = {
  'auth:login':     { capacity: 5,   refillPerSecond: 5 / 60 },
  'auth:register':  { capacity: 3,   refillPerSecond: 3 / 3600 },
  'prekeys:fetch':  { capacity: 30,  refillPerSecond: 30 / 60 },
  'prekeys:publish':{ capacity: 10,  refillPerSecond: 10 / 300 },
  'messages:send':  { capacity: 120, refillPerSecond: 2 },
  'messages:fetch': { capacity: 120, refillPerSecond: 2 },
  // Discovery is exact-match only; this bounds enumeration by guessing.
  'users:lookup':   { capacity: 60,  refillPerSecond: 1 },
  'presence:fetch': { capacity: 120, refillPerSecond: 2 },
  'attachments:upload': { capacity: 30, refillPerSecond: 0.5 },
  'attachments:fetch':  { capacity: 120, refillPerSecond: 2 },
  'reports:create': { capacity: 10,  refillPerSecond: 10 / 3600 },
  'auth:password':  { capacity: 5,   refillPerSecond: 5 / 300 },
  default:          { capacity: 60,  refillPerSecond: 1 },
};

class RateLimiter {
  constructor(clock = () => Date.now() / 1000) {
    this.clock = clock;
    this.state = new Map();
  }

  /** @returns {{allowed: boolean, retryAfter: number}} */
  check(bucketName, subject) {
    const config = BUCKETS[bucketName] || BUCKETS.default;
    const key = `${bucketName}|${subject}`;
    const nowSec = this.clock();
    let entry = this.state.get(key);
    if (!entry) {
      entry = { tokens: config.capacity, updated: nowSec };
      this.state.set(key, entry);
    }
    const elapsed = Math.max(0, nowSec - entry.updated);
    entry.tokens = Math.min(config.capacity, entry.tokens + elapsed * config.refillPerSecond);
    entry.updated = nowSec;

    if (entry.tokens < 1) {
      const retryAfter = Math.ceil((1 - entry.tokens) / config.refillPerSecond);
      return { allowed: false, retryAfter };
    }
    entry.tokens -= 1;
    return { allowed: true, retryAfter: 0 };
  }

  /** Bound memory: drop buckets that have fully refilled. */
  prune() {
    const nowSec = this.clock();
    for (const [key, entry] of this.state) {
      const bucketName = key.split('|')[0];
      const config = BUCKETS[bucketName] || BUCKETS.default;
      if (entry.tokens >= config.capacity && nowSec - entry.updated > 3600) {
        this.state.delete(key);
      }
    }
  }
}

module.exports = { RateLimiter, BUCKETS };
