/**
 * tss_2_of_3.ts — 2-of-3 threshold authorization demo (Shamir's Secret Sharing).
 *
 * EDUCATIONAL DEMONSTRATION ONLY. Not audited, not constant-time, not for
 * production key management. A production UZAP deployment would use an audited
 * threshold signature scheme (e.g. FROST) with real enclave attestation; this
 * module exists so the recovery flow in docs/rfc-9901-uzap.md can be executed
 * and inspected end-to-end. See "Security Considerations" in that document.
 */

import { randomBytes } from "node:crypto";

/** secp256k1 field prime: 2^256 − 2^32 − 977. All arithmetic happens mod p. */
export const FIELD_PRIME: bigint =
  0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;

export interface KeyShare {
  /** x-coordinate of the share (1, 2, 3, …). Never zero. */
  x: bigint;
  /** y-coordinate: f(x) for the sharing polynomial f. */
  y: bigint;
  /** Human label for the party holding this share (metadata only). */
  holder: string;
}

function mod(a: bigint, p: bigint): bigint {
  const r = a % p;
  return r >= 0n ? r : r + p;
}

/** Modular inverse via the extended Euclidean algorithm. */
function modInverse(a: bigint, p: bigint): bigint {
  let oldR = mod(a, p);
  let r = p;
  let oldS = 1n;
  let s = 0n;
  while (r !== 0n) {
    const q = oldR / r;
    const tmpR = oldR;
    oldR = r;
    r = tmpR - q * r;
    const tmpS = oldS;
    oldS = s;
    s = tmpS - q * s;
  }
  if (oldR !== 1n) throw new Error("no modular inverse exists");
  return mod(oldS, p);
}

/** Uniform random field element in [1, p − 1]. */
function randomFieldElement(p: bigint): bigint {
  for (;;) {
    const v = BigInt("0x" + randomBytes(32).toString("hex"));
    if (v > 0n && v < p) return v;
  }
}

/** Fresh random 256-bit master secret. */
export function generateMasterSecret(): bigint {
  return randomFieldElement(FIELD_PRIME);
}

/**
 * Split `secret` into `total` shares so that any `threshold` of them
 * reconstruct it (Shamir's Secret Sharing over FIELD_PRIME).
 *
 * Each share is a point (x, f(x)) on a random polynomial
 * f(x) = secret + a₁·x + a₂·x² + … of degree (threshold − 1).
 */
export function splitSecret(
  secret: bigint,
  threshold: number,
  total: number,
  holders: string[],
  prime: bigint = FIELD_PRIME,
): KeyShare[] {
  if (!Number.isInteger(threshold) || threshold < 2) {
    throw new Error("threshold must be an integer >= 2");
  }
  if (!Number.isInteger(total) || total < threshold) {
    throw new Error("total shares must be an integer >= threshold");
  }
  if (holders.length !== total) {
    throw new Error("holders must name every share");
  }
  if (secret <= 0n || secret >= prime) {
    throw new Error("secret must lie in the open interval (0, prime)");
  }

  const coeffs: bigint[] = [secret];
  for (let i = 1; i < threshold; i++) coeffs.push(randomFieldElement(prime));

  const shares: KeyShare[] = [];
  for (let i = 0; i < total; i++) {
    const x = BigInt(i + 1);
    let y = 0n;
    for (let d = coeffs.length - 1; d >= 0; d--) {
      y = mod(y * x + coeffs[d], prime);
    }
    shares.push({ x, y, holder: holders[i] });
  }
  return shares;
}

/**
 * Reconstruct the secret from the supplied shares via Lagrange interpolation
 * evaluated at x = 0. Fewer than `threshold` shares interpolate to *a* value,
 * but not the secret — which is exactly the security property being demoed.
 */
export function reconstructSecret(
  shares: KeyShare[],
  prime: bigint = FIELD_PRIME,
): bigint {
  if (shares.length === 0) throw new Error("at least one share is required");
  const seen = new Set(shares.map((s) => s.x.toString()));
  if (seen.size !== shares.length) {
    throw new Error("duplicate share x-coordinates");
  }

  let secret = 0n;
  for (let i = 0; i < shares.length; i++) {
    let num = 1n;
    let den = 1n;
    for (let j = 0; j < shares.length; j++) {
      if (i === j) continue;
      num = mod(num * mod(-shares[j].x, prime), prime);
      den = mod(den * mod(shares[i].x - shares[j].x, prime), prime);
    }
    const lagrange = mod(num * modInverse(den, prime), prime);
    secret = mod(secret + mod(shares[i].y * lagrange, prime), prime);
  }
  return secret;
}

/** Serialize a share for transport/storage (hex, JSON-safe). */
export function shareToJSON(s: KeyShare): {
  x: string;
  y: string;
  holder: string;
} {
  return {
    x: "0x" + s.x.toString(16),
    y: "0x" + s.y.toString(16),
    holder: s.holder,
  };
}

/** Deserialize a share produced by {@link shareToJSON}. */
export function shareFromJSON(o: {
  x: string;
  y: string;
  holder: string;
}): KeyShare {
  return { x: BigInt(o.x), y: BigInt(o.y), holder: o.holder };
}
