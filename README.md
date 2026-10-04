# UZAP Protocol

**Identity recovery without central data exposure.** UZAP combines W3C
Decentralized Identifiers (DIDs), 2-of-3 threshold authorization, an
independent MPC co-signer enclave, and zero-knowledge state broadcast so a
user can recover or rotate their identifier without any single party —
or central database — holding enough to impersonate them.

> **Status:** Phase-1 scaffold / draft specification (v0.1.0). The spec is a
> proposal, not a ratified standard, and the code is an educational
> demonstration, not audited production cryptography. See
> [docs/rfc-9901-uzap.md](docs/rfc-9901-uzap.md) § Security Considerations.

## Principles

- **Open governance** — public, Apache-2.0 licensed, community-auditable.
- **Non-proprietary portability** — built on W3C DID Core, not a vendor lock-in.
- **No central data exposure** — no party ever holds the full master secret;
  any 2 of 3 independent shares authorize recovery, 1 share reveals nothing.

## Repository map

```
uzap-protocol/
├── LICENSE                    Apache-2.0
├── README.md
├── docs/
│   └── rfc-9901-uzap.md         Draft specification: 4-layer architecture,
│                                2-of-3 flow, enclave + ZK broadcast design
├── schemas/
│   └── did-document.json        Example W3C DID document (placeholder keys)
└── src/
    ├── core/
    │   └── did.ts               DID document model, validation, recovery events
    ├── crypto/
    │   └── tss_2_of_3.ts        2-of-3 Shamir secret sharing (BigInt, no deps)
    └── index.ts                 Executable end-to-end demo
```

## Quickstart

Requires Node.js ≥ 18.

```bash
npm install
npm run demo
```

The demo runs the full Phase-1 flow: key ceremony → DID document creation and
validation → 2-of-3 reconstruction (all three pairs) → single-share negative
check → recovery-event authorization and verification (plus a wrong-key
negative check).

## What this is / isn't

| | Demo (this repo) | Production target |
|---|---|---|
| Threshold scheme | Shamir secret sharing + HMAC | Audited TSS (e.g. FROST) — shares never reconstruct centrally |
| Co-signer | Simulated party label | Attested enclave (AWS Nitro / SGX) with MPC |
| State proof | HMAC over canonical JSON | Real ZK circuit proving authorization without revealing shares |
| Broadcast | Logged to console | Trust-fabric broadcast with checkpoint binding |

## License

Apache License 2.0 — see [LICENSE](LICENSE).

## Acknowledgments

Originated by **Crystal Lee Pope**. Specification contributed by
**Parkerlee Marie-Gemini**; scaffold implemented by **Novara Ann-Muse**.
