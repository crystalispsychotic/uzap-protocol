/**
 * did.ts — minimal W3C DID document model plus recovery-event helpers.
 *
 * The authorization MAC here (HMAC-SHA256 keyed by the reconstructed master
 * secret) stands in for a production threshold signature. It demonstrates the
 * *flow* — 2 shares → reconstruct → authorize → verify — not production
 * cryptography. See docs/rfc-9901-uzap.md, "Security Considerations".
 */

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyMultibase?: string;
}

export interface DidDocument {
  "@context": string[];
  id: string;
  controller: string[];
  verificationMethod: VerificationMethod[];
  authentication: string[];
  assertionMethod: string[];
  service?: Array<{ id: string; type: string; serviceEndpoint: string }>;
}

export interface RecoveryEvent {
  type: "UZAPRecoveryEvent";
  /** DID whose identifier is being updated. */
  did: string;
  previousIdentifier: string;
  newIdentifier: string;
  /** Fresh randomness so every recovery event is unique. */
  nonce: string;
  /** ISO-8601 timestamp. */
  issuedAt: string;
}

export interface AuthorizedRecovery {
  event: RecoveryEvent;
  /** Hex-encoded HMAC-SHA256 over the canonical event JSON. Demo only. */
  authorization: string;
}

/** Build a DID document with one verification method per named node. */
export function createDidDocument(
  did: string,
  methods: Array<{ fragment: string; type: string; publicKeyMultibase: string }>,
): DidDocument {
  const verificationMethod: VerificationMethod[] = methods.map((m) => ({
    id: `${did}#${m.fragment}`,
    type: m.type,
    controller: did,
    publicKeyMultibase: m.publicKeyMultibase,
  }));
  const refs = verificationMethod.map((m) => m.id);
  return {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/multikey/v1",
    ],
    id: did,
    controller: [did],
    verificationMethod,
    authentication: refs.slice(0, 2),
    assertionMethod: refs,
    service: [
      {
        id: `${did}#recovery`,
        type: "UZAPRecovery",
        serviceEndpoint: "https://example.invalid/uzap/recovery",
      },
    ],
  };
}

/**
 * Structural validation of a DID document. Returns a list of problems;
 * an empty list means the document is well-formed (not that keys are real).
 */
export function validateDidDocument(doc: unknown): string[] {
  const problems: string[] = [];
  if (typeof doc !== "object" || doc === null) {
    return ["document must be an object"];
  }
  const d = doc as Record<string, unknown>;

  if (
    !Array.isArray(d["@context"]) ||
    !(d["@context"] as unknown[]).includes("https://www.w3.org/ns/did/v1")
  ) {
    problems.push('@context must include "https://www.w3.org/ns/did/v1"');
  }
  if (typeof d["id"] !== "string" || !(d["id"] as string).startsWith("did:")) {
    problems.push('id must be a string starting with "did:"');
  }
  if (!Array.isArray(d["controller"]) || (d["controller"] as unknown[]).length === 0) {
    problems.push("controller must be a non-empty array");
  }

  const methods = d["verificationMethod"];
  if (!Array.isArray(methods) || methods.length === 0) {
    problems.push("verificationMethod must be a non-empty array");
    return problems;
  }
  const ids = new Set<string>();
  for (const m of methods as Array<Record<string, unknown>>) {
    if (typeof m["id"] !== "string") {
      problems.push("every verificationMethod needs a string id");
      continue;
    }
    const id = m["id"] as string;
    if (ids.has(id)) problems.push(`duplicate verificationMethod id: ${id}`);
    ids.add(id);
    if (typeof d["id"] === "string" && !id.startsWith(d["id"] as string)) {
      problems.push(`verificationMethod id not scoped to document: ${id}`);
    }
    if (typeof m["type"] !== "string") {
      problems.push(`verificationMethod ${id} needs a type`);
    }
  }
  for (const rel of ["authentication", "assertionMethod"]) {
    const refs = d[rel];
    if (!Array.isArray(refs)) {
      problems.push(`${rel} must be an array`);
      continue;
    }
    for (const ref of refs as unknown[]) {
      if (typeof ref !== "string" || !ids.has(ref)) {
        problems.push(`${rel} references unknown verificationMethod: ${String(ref)}`);
      }
    }
  }
  return problems;
}

/** Construct an identifier-update (recovery) event for a DID. */
export function buildRecoveryEvent(
  did: string,
  previousIdentifier: string,
  newIdentifier: string,
): RecoveryEvent {
  return {
    type: "UZAPRecoveryEvent",
    did,
    previousIdentifier,
    newIdentifier,
    nonce: randomBytes(16).toString("hex"),
    issuedAt: new Date().toISOString(),
  };
}

/** Deterministic JSON encoding: object keys sorted recursively. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map((v) => canonicalJson(v)).join(",") + "]";
  }
  const keys = Object.keys(value as Record<string, unknown>).sort();
  return (
    "{" +
    keys
      .map((k) => JSON.stringify(k) + ":" + canonicalJson((value as Record<string, unknown>)[k]))
      .join(",") +
    "}"
  );
}

function secretToKey(secret: bigint): Buffer {
  return Buffer.from(secret.toString(16).padStart(64, "0"), "hex");
}

/**
 * Authorize a recovery event with the reconstructed master secret.
 * DEMO ONLY — production uses a true threshold signature (e.g. FROST).
 */
export function authorizeRecovery(
  secret: bigint,
  event: RecoveryEvent,
): AuthorizedRecovery {
  const mac = createHmac("sha256", secretToKey(secret));
  mac.update(canonicalJson(event), "utf8");
  return { event, authorization: mac.digest("hex") };
}

/** Verify an authorized recovery event against the master secret. */
export function verifyRecoveryAuthorization(
  secret: bigint,
  authorized: AuthorizedRecovery,
): boolean {
  const expected = authorizeRecovery(secret, authorized.event).authorization;
  const a = Buffer.from(expected, "hex");
  const b = Buffer.from(authorized.authorization, "hex");
  return a.length === b.length && timingSafeEqual(a, b);
}
