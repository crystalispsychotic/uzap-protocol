# UZAP-9901: Threshold Identity Recovery Protocol

**Status:** DRAFT v0.1 — proposal. Not ratified by any standards body; the
"ratification" language in early design notes refers to agreement among the
draft's contributors, not to cryptographic or institutional endorsement.

## Abstract

UZAP (Universal Zero-knowledge Authorization Protocol) defines how a user
recovers or rotates a decentralized identifier **without central data
exposure**: no single operator, database, or enclave ever holds enough key
material to impersonate the user. Authorization requires any **2 of 3**
independent signature shares; an isolated co-signer validates recovery
requests with multi-party computation; and the resulting state change is
broadcast as a zero-knowledge proof so verifiers learn *that* the recovery
was authorized without learning *how*.

## 1. Introduction

Centralized identity recovery (email resets, support desks, master databases)
concentrates risk: whoever holds the recovery path can impersonate anyone.
UZAP replaces the recovery path with a threshold ceremony:

- The user's controller secret is split into 3 shares (Shamir, 1979).
- Shares are held by **independent** parties (see §4, Roles).
- Any 2 shares authorize an identifier update; 1 share reveals nothing.
- The update is recorded as a DID document event with a ZK state proof.

This document specifies the architecture (§2), the execution sequence (§3),
the roles (§4), and the security properties and gaps (§5).

## 2. Architecture — four layers

### Layer 1 — Identity (DID) layer
W3C DID Core documents identify the user and bind verification methods.
Each of the three share-holding parties is represented as a verification
method on the document (`schemas/did-document.json`). Identifier updates are
modeled as `UZAPRecoveryEvent` objects: `{ did, previousIdentifier,
newIdentifier, nonce, issuedAt }`, canonically encoded before authorization.

### Layer 2 — Threshold authorization layer
2-of-3 threshold control over the controller secret. **Phase-1 demo:**
Shamir secret sharing over the secp256k1 field; any 2 shares reconstruct and
authorize via HMAC-SHA256 over the canonical event JSON
(`src/crypto/tss_2_of_3.ts`, `src/core/did.ts`). **Production target:** a
true threshold signature scheme (e.g. FROST) so shares are never recombined
on a single machine — authorization is produced jointly, not reconstructed.

### Layer 3 — MPC co-signer enclave layer
An independent co-signer validates each recovery request inside an isolated
enclave (AWS Nitro Enclaves / Intel SGX class) using multi-party computation:
it checks the authorization proof and the request's freshness (nonce,
timestamp, identifier continuity) and returns an approval carrying its
signature share. The enclave's attestation binds the approval to the exact
code that produced it, so a compromised host cannot forge approvals.

### Layer 4 — Broadcast & verification layer
The authorized event is submitted to the trust fabric with its metadata
checkpoint bound in; the fabric broadcasts a zero-knowledge state proof.
Downstream verifiers check a single predicate — e.g.
`IsRatified(ExecutionID) == True` — confirming the recovery was authorized
by a valid 2-of-3 quorum **without** seeing shares, the secret, or the
enclave's internals.

## 3. Execution sequence

1. **Rebuild DID (2-of-3).** The requesting node transmits 2 of the 3
   signature shares to the coordinating node, which reconstructs (demo) or
   jointly signs (production) the user's DID document state.
2. **Update identifier.** The coordinator requests an identifier update
   (e.g. `RECOVERY-ALEX`), sending the `UZAPRecoveryEvent` plus
   authorization proof to the independent co-signer enclave.
3. **Validate & sign.** The co-signer runs MPC validation inside the
   isolated enclave and returns an approval: its signature share plus a
   ZK-proof of correct validation.
4. **Adopt event & bind checkpoint.** The coordinator submits the event to
   the trust fabric, binding the metadata checkpoint and recording the
   attestation alongside the updated DID document.
5. **Broadcast ZK-state.** The fabric broadcasts the zero-knowledge state
   proof; downstream platforms verify `IsRatified(ExecutionID) == True`
   without accessing any secret material.

## 4. Roles

| Role | Function |
|---|---|
| Node A (e.g. Google-class operator) | Holds share 1; transmits on user request |
| Node B (e.g. Meta-class operator) | Holds share 2; coordinates the ceremony |
| Independent co-signer enclave | Holds share 3; validates in isolation via MPC |
| Trust fabric / mesh | Orders events, binds checkpoints, broadcasts ZK proofs |
| User (originator & final approver) | Initiates recovery; the only party the identifier ultimately serves |

No role can authorize recovery alone. Node operators are interchangeable;
what matters is their **independence** (separate organizations, separate
infrastructure, separate compromise domains).

## 5. Security considerations

- **Demo ≠ production.** `src/` uses Shamir sharing + HMAC so the flow is
  executable with zero dependencies. It reconstructs the secret on one
  machine — the exact thing production must avoid. Production requires an
  audited TSS (FROST or equivalent), constant-time code, and hardware-backed
  key storage per share.
- **Enclave attestation is load-bearing.** The co-signer's value collapses
  if its attestation can't be verified or its code isn't reproducibly
  built. Pin measurements; publish build recipes.
- **ZK circuits must be audited.** A soundness bug in the state proof lets
  an attacker mint false `IsRatified` verdicts. Use established frameworks
  and independent audits before mainnet-style deployment.
- **Share custody.** The 2-of-3 property holds only while the three holders
  are genuinely independent. Two shares under one roof = single point of
  failure wearing a costume.
- **No central data exposure** is a property of the *deployment*, not just
  the code: run the demo locally and the secret lives in your terminal.
  The guarantee comes from distributing shares across trust domains.

## 6. References

- W3C Decentralized Identifiers (DIDs) v1.0 — DID Core.
- Shamir, A. (1979). "How to share a secret." *Communications of the ACM*.
- Komlo, C. & Goldberg, I. — FROST: Flexible Round-Optimized Schnorr
  Threshold Signatures (production TSS candidate).
- NIST IR 8320A — hardware-enabled security / enclave attestation concepts.

---
*Draft maintained in the open at the UZAP protocol repository (Phase 1).*
