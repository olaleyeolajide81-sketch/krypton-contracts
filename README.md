# Krypton Contracts

Zero-knowledge invoice factoring on Stellar. A Noir circuit proves invoice eligibility without revealing sensitive details; a Soroban smart contract verifies the proof on-chain.

---

## Overview

| Component | Path | Description |
|---|---|---|
| ZK Circuit | `circuits/factoring/` | Noir (Ultrahonk) circuit that commits to invoice data and asserts eligibility |
| Soroban Contract | `contracts/zk_factoring/` | Rust/Soroban contract that verifies proofs and manages nullifiers |

### How it works

1. A supplier generates a Noir proof off-chain, committing to `(invoice_amount, supplier_id, buyer_id, salt)` via Poseidon2 and asserting `invoice_amount > 1000`.
2. The proof, along with three public inputs — `commitment`, `eligibility_flag`, and `nullifier` — is submitted to the Soroban contract.
3. The contract verifies the proof using the CAP-0080 BN254 host function, checks the nullifier has not been used before, and stores it to prevent replay.
4. Discount calculation is available as a separate contract call using CAP-0082 checked 256-bit arithmetic.

---

## Circuit — `circuits/factoring`

**Language:** Noir  
**Backend:** Barretenberg (Ultrahonk)  
**Commitment scheme:** Stellar X-Ray Poseidon2

### Private inputs (witness-only)

| Name | Type | Description |
|---|---|---|
| `priv_invoice_amount` | Field (u128) | Invoice value |
| `priv_supplier_id` | Field (u64) | Supplier identifier |
| `priv_buyer_id` | Field (u64) | Buyer identifier |
| `priv_invoice_salt` | Field (u128) | Random blinding factor |

### Public outputs

| Name | Type | Description |
|---|---|---|
| `pub_commitment` | Field | `Poseidon2(amount, supplier_id, buyer_id, salt)` |
| `pub_eligibility` | Field | `1` if `invoice_amount > 1000`, else `0` |

### Constraints

- Recomputes the Poseidon2 commitment and asserts it equals `pub_commitment`.
- Range-checks `invoice_amount - 1000` to 64 bits, ensuring `invoice_amount >= 1000`.
- Asserts `pub_eligibility == 1`.

### Build & test

```bash
# Install Noir toolchain: https://noir-lang.org/docs/getting_started/installation
nargo check
nargo test
nargo prove   # generates proof artifact
```

---

## Soroban Contract — `contracts/zk_factoring`

**Language:** Rust (no_std)  
**SDK:** soroban-sdk 21.0.0  
**Network:** Stellar (Protocol 26+)

### Contract functions

#### `verify_invoice_proof(proof_bytes, public_inputs) → Result<bool, FactoringError>`

Verifies a Noir Ultrahonk proof.

- `proof_bytes` — serialized Ultrahonk proof from Barretenberg
- `public_inputs` — `Vec<BytesN<32>>` with exactly 3 elements:
  1. `commitment`
  2. `eligibility_flag`
  3. `nullifier`

Stores the nullifier in persistent storage on success to prevent replay attacks.

#### `calculate_discount(invoice_amount, discount_bps) → Result<u128, FactoringError>`

Computes `(invoice_amount × discount_bps) / 10_000` using checked arithmetic.

- `discount_bps` — basis points (e.g. `150` = 1.5%)

### Error codes

| Code | Value | Meaning |
|---|---|---|
| `ProofVerificationFailed` | 1 | BN254 pairing check returned false |
| `NullifierAlreadyUsed` | 2 | Replay attempt detected |
| `InvalidPublicInputCount` | 3 | `public_inputs` length ≠ 3 |
| `DiscountOverflow` | 4 | Arithmetic overflow in discount calculation |

### Build & test

```bash
# Install Rust + Soroban CLI: https://developers.stellar.org/docs/tools/developer-tools
cargo build --target wasm32-unknown-unknown --release
cargo test
```

### Deploy

```bash
stellar contract deploy \
  --wasm target/wasm32-unknown-unknown/release/zk_factoring.wasm \
  --source <YOUR_SECRET_KEY> \
  --network testnet
```

---

## Prerequisites

- [Rust](https://rustup.rs/) with `wasm32-unknown-unknown` target
- [Noir / Nargo](https://noir-lang.org/docs/getting_started/installation)
- [Barretenberg](https://github.com/AztecProtocol/barretenberg) for proof generation
- [Stellar CLI](https://developers.stellar.org/docs/tools/developer-tools/stellar-cli)

---

## License

MIT
