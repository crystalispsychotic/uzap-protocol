/**
 * index.ts — executable Phase-1 demonstration of the UZAP recovery flow:
 *
 *   1. A controller master secret is split into 3 shares (2-of-3 threshold).
 *   2. A W3C DID document is created and structurally validated.
 *   3. Any 2 shares reconstruct the secret; 1 share provably does not.
 *   4. The reconstructed secret authorizes an identifier-update
 *      (recovery) event; authorization verifies, and a wrong key fails.
 *
 * Run:  npm run demo
 */

import {
  generateMasterSecret,
  reconstructSecret,
  shareToJSON,
  splitSecret,
} from "./crypto/tss_2_of_3.js";
import {
  authorizeRecovery,
  buildRecoveryEvent,
  createDidDocument,
  validateDidDocument,
  verifyRecoveryAuthorization,
} from "./core/did.js";

function section(title: string): void {
  console.log("\n=== " + title + " ===");
}

function main(): void {
  console.log("UZAP Phase-1 demo — 2-of-3 threshold identity recovery");
  console.log("(educational demo; see docs/rfc-9901-uzap.md § Security Considerations)");

  // 1. Split the controller master secret across three parties.
  section("1. Key ceremony — split master secret 2-of-3");
  const master = generateMasterSecret();
  const holders = ["google-node", "meta-node", "cosigner-enclave"];
  const shares = splitSecret(master, 2, 3, holders);
  for (const s of shares) {
    console.log(`  share x=${s.x} → ${s.holder}`);
  }
  console.log("  (shares would be transmitted to independent parties)");

  // 2. Create and validate the DID document.
  section("2. DID document — create + validate");
  const did = "did:uzap:demo-alex-01";
  const doc = createDidDocument(did, [
    {
      fragment: "google-node",
      type: "Multikey",
      publicKeyMultibase: "zExampleGoogleNodePublicKey000000000000000001",
    },
    {
      fragment: "meta-node",
      type: "Multikey",
      publicKeyMultibase: "zExampleMetaNodePublicKey000000000000000000002",
    },
    {
      fragment: "cosigner-enclave",
      type: "Multikey",
      publicKeyMultibase: "zExampleCosignerEnclavePublicKey000000000000003",
    },
  ]);
  const problems = validateDidDocument(doc);
  console.log(
    problems.length === 0
      ? "  document valid ✓"
      : "  problems:\n" + problems.map((p) => "  - " + p).join("\n"),
  );
  void shareToJSON; // (serialization helpers available for transport)

  // 3. Threshold reconstruction: any 2 of 3 shares work.
  section("3. Recovery — 2-of-3 reconstruction");
  const combos: Array<[number, number]> = [
    [0, 1],
    [0, 2],
    [1, 2],
  ];
  for (const [a, b] of combos) {
    const reconstructed = reconstructSecret([shares[a], shares[b]]);
    const ok = reconstructed === master;
    console.log(
      `  shares [${holders[a]}, ${holders[b]}] → reconstructs master: ${ok ? "YES ✓" : "NO ✗"}`,
    );
    if (!ok) throw new Error("threshold reconstruction failed");
  }

  // 4. A single share reveals nothing.
  section("4. Security property — 1 share is not enough");
  const partial = reconstructSecret([shares[1]]);
  console.log(
    `  single share [${holders[1]}] reconstructs master: ${partial === master ? "YES ✗ (BAD)" : "NO ✓ (expected)"}`,
  );
  if (partial === master) throw new Error("single share must not reconstruct");

  // 5. Authorize an identifier-update (recovery) event.
  section("5. Identifier update — authorize + verify");
  const recovered = reconstructSecret([shares[0], shares[2]]);
  const event = buildRecoveryEvent(did, "demo-alex-01", "RECOVERY-ALEX");
  console.log(`  event: ${event.previousIdentifier} → ${event.newIdentifier}`);
  const authorized = authorizeRecovery(recovered, event);
  console.log(`  authorization: ${authorized.authorization.slice(0, 32)}…`);
  const valid = verifyRecoveryAuthorization(recovered, authorized);
  console.log(`  verifies with reconstructed secret: ${valid ? "YES ✓" : "NO ✗"}`);
  if (!valid) throw new Error("authorization verification failed");

  const forged = verifyRecoveryAuthorization(partial, authorized);
  console.log(
    `  verifies with wrong key: ${forged ? "YES ✗ (BAD)" : "NO ✓ (expected)"}`,
  );
  if (forged) throw new Error("wrong-key authorization must fail");

  section("DONE — all checks passed");
}

main();
