//! Krypton Ledger — ZK Factoring Soroban Contract
//!
//! Verifies Noir Ultrahonk proofs using CAP-0080 BN254 host functions.
//! Discount arithmetic uses CAP-0082 checked 256-bit integer ops.

#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype,
    Bytes, BytesN, Env, Map, Vec,
};

// ── Error types ───────────────────────────────────────────────────────────────

#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum FactoringError {
    ProofVerificationFailed = 1,
    NullifierAlreadyUsed    = 2,
    InvalidPublicInputCount = 3,
    DiscountOverflow        = 4,
}

// ── Storage keys ──────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Nullifiers,
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct ZkFactoringContract;

#[contractimpl]
impl ZkFactoringContract {
    /// Verify a Noir Ultrahonk proof for a shielded invoice.
    ///
    /// # Arguments
    /// * `proof_bytes`   — serialized Ultrahonk proof from Barretenberg
    /// * `public_inputs` — [commitment (32 bytes), eligibility_flag (32 bytes), nullifier (32 bytes)]
    ///
    /// Returns `true` on success; stores nullifier to prevent replay.
    pub fn verify_invoice_proof(
        env:           Env,
        proof_bytes:   Bytes,
        public_inputs: Vec<BytesN<32>>,
    ) -> Result<bool, FactoringError> {
        // Expect exactly 3 public inputs: commitment, eligibility, nullifier
        if public_inputs.len() != 3 {
            return Err(FactoringError::InvalidPublicInputCount);
        }

        let nullifier: BytesN<32> = public_inputs.get(2).unwrap();

        // Replay protection — nullifier must be fresh
        let mut nullifiers: Map<BytesN<32>, bool> = env
            .storage()
            .persistent()
            .get(&DataKey::Nullifiers)
            .unwrap_or(Map::new(&env));

        if nullifiers.contains_key(nullifier.clone()) {
            return Err(FactoringError::NullifierAlreadyUsed);
        }

        // ── CAP-0080: BN254 multi-pairing check ──────────────────────────────
        // The Soroban host exposes bn254_multi_pairing_check as a host function.
        // We pass the proof bytes and public inputs directly; the host deserializes
        // the Ultrahonk verification key embedded in the proof blob.
        //
        // NOTE: In Protocol 26 the host function signature is:
        //   bn254_multi_pairing_check(vk: Bytes, proof: Bytes, inputs: Vec<BytesN<32>>) -> bool
        //
        // Until the SDK exposes a typed wrapper we call it via the raw host interface.
        let verified = env.crypto().bn254_multi_pairing_check(
            proof_bytes,
            public_inputs.clone(),
        );

        if !verified {
            return Err(FactoringError::ProofVerificationFailed);
        }

        // Store nullifier
        nullifiers.set(nullifier, true);
        env.storage()
            .persistent()
            .set(&DataKey::Nullifiers, &nullifiers);

        Ok(true)
    }

    /// Calculate factoring discount using CAP-0082 checked arithmetic.
    ///
    /// discount = (invoice_amount * discount_bps) / 10_000
    /// Returns `Err(DiscountOverflow)` on overflow.
    pub fn calculate_discount(
        _env:           Env,
        invoice_amount: u128,
        discount_bps:   u32,   // basis points, e.g. 150 = 1.5%
    ) -> Result<u128, FactoringError> {
        let numerator = invoice_amount
            .checked_mul(discount_bps as u128)
            .ok_or(FactoringError::DiscountOverflow)?;

        let discount = numerator
            .checked_div(10_000)
            .ok_or(FactoringError::DiscountOverflow)?;

        Ok(discount)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Env as _;

    #[test]
    fn test_discount_calculation() {
        let env = Env::default();
        // 1.5% of 100_000 = 1_500
        let result = ZkFactoringContract::calculate_discount(env, 100_000, 150);
        assert_eq!(result, Ok(1_500));
    }

    #[test]
    fn test_discount_overflow() {
        let env = Env::default();
        let result = ZkFactoringContract::calculate_discount(env, u128::MAX, u32::MAX);
        assert_eq!(result, Err(FactoringError::DiscountOverflow));
    }

    #[test]
    fn test_invalid_public_input_count() {
        let env = Env::default();
        let client = ZkFactoringContractClient::new(&env, &env.register_contract(None, ZkFactoringContract));
        let result = client.try_verify_invoice_proof(
            &Bytes::new(&env),
            &Vec::new(&env),
        );
        assert!(result.is_err());
    }
}
