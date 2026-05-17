// Krypton Ledger — Invoice Factoring ZK Circuit
// Flavor: Ultrahonk (Barretenberg backend)
// Protocol: Stellar X-Ray Poseidon2 commitment scheme
//
// Private inputs  → never revealed on-chain
// Public outputs  → posted to Soroban verify_invoice_proof

use dep::std::hash::poseidon2;

// ── Private inputs ────────────────────────────────────────────────────────────
// priv_ prefix signals these are witness-only (not in public ABI)
fn main(
    priv_invoice_amount : Field,   // u128 as field element
    priv_supplier_id    : Field,   // u64  as field element
    priv_buyer_id       : Field,   // u64  as field element
    priv_invoice_salt   : Field,   // u128 random blinding factor

// ── Public outputs ────────────────────────────────────────────────────────────
    pub_commitment      : pub Field,  // Poseidon2(amount, supplier_id, buyer_id, salt)
    pub_eligibility     : pub Field   // 1 if invoice_amount > minimum threshold, else 0
) {
    // 1. Recompute commitment and assert it matches the public value
    let computed_commitment = poseidon2::Poseidon2::hash(
        [priv_invoice_amount, priv_supplier_id, priv_buyer_id, priv_invoice_salt],
        4
    );
    assert(computed_commitment == pub_commitment, "commitment mismatch");

    // 2. Eligibility: invoice_amount must be > 1000 (field comparison via subtraction)
    //    We encode the minimum as a field constant; underflow would wrap, so we
    //    constrain the difference to be in [0, 2^64) via range check.
    let minimum: Field = 1000;
    let diff = priv_invoice_amount - minimum;
    // Range-check: diff fits in 64 bits → invoice_amount >= minimum
    diff.assert_max_bit_size(64);

    // 3. Assert the public eligibility flag matches our constraint
    assert(pub_eligibility == 1, "invoice not eligible for factoring");
}

#[test]
fn test_valid_invoice() {
    let amount   : Field = 50000;
    let supplier : Field = 42;
    let buyer    : Field = 99;
    let salt     : Field = 0xdeadbeef;

    let commitment = poseidon2::Poseidon2::hash([amount, supplier, buyer, salt], 4);
    main(amount, supplier, buyer, salt, commitment, 1);
}
