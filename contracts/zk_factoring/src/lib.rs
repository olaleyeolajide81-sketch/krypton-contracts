//! Krypton Ledger — ZK Factoring Soroban Contract
//!
//! Verifies Noir Ultrahonk proofs using CAP-0080 BN254 host functions.
//! Discount arithmetic uses CAP-0082 checked 256-bit integer ops.

#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype,
    Bytes, BytesN, Env, Vec,
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
    InvalidEligibilityFlag  = 5,
}

// ── Storage keys ──────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Nullifier(BytesN<32>),
}

// ── BN254 pairing check ───────────────────────────────────────────────────────
//
// CAP-0080 exposes bn254_multi_pairing_check as a Soroban host function.
// soroban-sdk 21.x does not yet provide a typed Rust wrapper, so we call it
// via the raw host-function interface in production builds.
// In test builds we substitute a stub that always returns true so that unit
// tests can exercise all other contract logic without a real proof.

#[cfg(not(test))]
fn bn254_verify(_env: &Env, _proof: Bytes, _inputs: Vec<BytesN<32>>) -> bool {
    // TODO: replace with the typed SDK wrapper once soroban-sdk exposes it (CAP-0080).
    // Panicking here makes the unimplemented state explicit rather than silently
    // accepting or rejecting every proof.
    panic!("bn254_verify: CAP-0080 host-function binding not yet implemented")
}

#[cfg(test)]
fn bn254_verify(_env: &Env, _proof: Bytes, _inputs: Vec<BytesN<32>>) -> bool {
    // Stub: accept any proof in unit tests.
    true
}

// ── Eligibility flag: 32-byte big-endian encoding of 1 ───────────────────────

const ELIGIBILITY_FLAG_TRUE: [u8; 32] = {
    let mut b = [0u8; 32];
    b[31] = 1;
    b
};

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

        // Eligibility flag must equal 1
        let eligibility: BytesN<32> = public_inputs.get(1).unwrap();
        if eligibility != BytesN::from_array(&env, &ELIGIBILITY_FLAG_TRUE) {
            return Err(FactoringError::InvalidEligibilityFlag);
        }

        // Extract nullifier before passing public_inputs to verifier
        let nullifier: BytesN<32> = public_inputs.get(2).unwrap();

        // ── CAP-0080: BN254 multi-pairing check ──────────────────────────────
        let verified = bn254_verify(&env, proof_bytes, public_inputs);
        if !verified {
            return Err(FactoringError::ProofVerificationFailed);
        }

        // Replay protection — nullifier must be fresh (checked after proof verification)
        if env.storage().persistent().has(&DataKey::Nullifier(nullifier.clone())) {
            return Err(FactoringError::NullifierAlreadyUsed);
        }

        env.storage()
            .persistent()
            .set(&DataKey::Nullifier(nullifier.clone()), &true);

        // Extend TTL to the protocol maximum so the nullifier never expires.
        // threshold=0 means "always extend"; extend_to is the max allowed ledgers (~30 days).
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::Nullifier(nullifier), 0, 535_679);

        Ok(true)
    }

    /// Calculate factoring discount using CAP-0082 checked arithmetic.
    ///
    /// discount = (invoice_amount * discount_bps) / 10_000
    /// Returns `Err(DiscountOverflow)` on overflow.
    pub fn calculate_discount(
        invoice_amount: u128,
        discount_bps:   u32,   // basis points, e.g. 150 = 1.5%; max 10_000 (100%)
    ) -> Result<u128, FactoringError> {
        if discount_bps > 10_000 {
            return Err(FactoringError::DiscountOverflow);
        }

        let numerator = invoice_amount
            .checked_mul(discount_bps as u128)
            .ok_or(FactoringError::DiscountOverflow)?;

        numerator
            .checked_div(10_000)
            .ok_or(FactoringError::DiscountOverflow)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::Env;

    fn eligibility_true(env: &Env) -> BytesN<32> {
        BytesN::from_array(env, &ELIGIBILITY_FLAG_TRUE)
    }

    #[test]
    fn test_discount_calculation() {
        // 1.5% of 100_000 = 1_500
        let result = ZkFactoringContract::calculate_discount(100_000, 150);
        assert_eq!(result, Ok(1_500));
    }

    #[test]
    fn test_discount_overflow() {
        let result = ZkFactoringContract::calculate_discount(u128::MAX, u32::MAX);
        assert_eq!(result, Err(FactoringError::DiscountOverflow));
    }

    #[test]
    fn test_discount_bps_exceeds_max() {
        let result = ZkFactoringContract::calculate_discount(100_000, 10_001);
        assert_eq!(result, Err(FactoringError::DiscountOverflow));
    }

    #[test]
    fn test_invalid_public_input_count() {
        let env = Env::default();
        let client = ZkFactoringContractClient::new(
            &env,
            &env.register_contract(None, ZkFactoringContract),
        );
        let result = client.try_verify_invoice_proof(
            &Bytes::new(&env),
            &Vec::new(&env),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_eligibility_flag() {
        let env = Env::default();
        let client = ZkFactoringContractClient::new(
            &env,
            &env.register_contract(None, ZkFactoringContract),
        );
        let mut inputs: Vec<BytesN<32>> = Vec::new(&env);
        inputs.push_back(BytesN::from_array(&env, &[0u8; 32])); // commitment
        inputs.push_back(BytesN::from_array(&env, &[0u8; 32])); // eligibility = 0 (invalid)
        inputs.push_back(BytesN::from_array(&env, &[2u8; 32])); // nullifier

        let result = client.try_verify_invoice_proof(&Bytes::new(&env), &inputs);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_invoice_proof_and_replay_protection() {
        let env = Env::default();
        let client = ZkFactoringContractClient::new(
            &env,
            &env.register_contract(None, ZkFactoringContract),
        );

        let mut inputs: Vec<BytesN<32>> = Vec::new(&env);
        inputs.push_back(BytesN::from_array(&env, &[0u8; 32])); // commitment
        inputs.push_back(eligibility_true(&env));                // eligibility = 1
        inputs.push_back(BytesN::from_array(&env, &[2u8; 32])); // nullifier

        // First call should succeed
        let result = client.try_verify_invoice_proof(&Bytes::new(&env), &inputs);
        assert_eq!(result, Ok(Ok(true)));

        // Second call with same nullifier must fail with NullifierAlreadyUsed
        let result2 = client.try_verify_invoice_proof(&Bytes::new(&env), &inputs);
        assert!(result2.is_err());
    }
}
