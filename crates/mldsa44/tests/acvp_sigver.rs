//! # ACVP ML-DSA-44 sigVer Test Harness
//!
//! Reads vendored ACVP test vectors from `tests/vectors/acvp_mldsa44_sigver.json`
//! and validates each through `verify_pk()`.
//!
//! ## Adding real NIST vectors
//!
//! 1. Obtain ML-DSA-44 sigVer vectors from NIST ACVP
//! 2. Replace the placeholder entries in the JSON file
//! 3. Each entry: { "tcId": N, "pk": "hex", "message": "hex", "signature": "hex", "expected": bool }
//! 4. `cargo test -p andna-mldsa44 --test acvp_sigver`
//!
//! The test automatically skips placeholder entries (tcId == 0 or empty pk).

#[cfg(feature = "oqs-backend")]
mod acvp {
    use andna_contracts::SIG_LEN;
    use andna_mldsa44::{verify_pk, MlDsa44Error, ML_DSA_44_PK_LEN};

    /// One ACVP sigVer test case.
    struct AcvpVector {
        tc_id: u64,
        pk: Vec<u8>,
        message: Vec<u8>,
        signature: Vec<u8>,
        expected: bool,
    }

    /// Parse the vendored JSON vectors.
    fn load_acvp_vectors() -> Vec<AcvpVector> {
        let json_str = include_str!("vectors/acvp_mldsa44_sigver.json");
        let arr: serde_json::Value =
            serde_json::from_str(json_str).expect("ACVP vector JSON parse failed");

        let entries = arr.as_array().expect("ACVP JSON must be an array");

        entries
            .iter()
            .filter_map(|entry| {
                let tc_id = entry.get("tcId")?.as_u64()?;
                let pk_hex = entry.get("pk")?.as_str()?;
                let msg_hex = entry.get("message")?.as_str()?;
                let sig_hex = entry.get("signature")?.as_str()?;
                let expected = entry.get("expected")?.as_bool()?;

                // Skip placeholder entries
                if tc_id == 0 || pk_hex.is_empty() {
                    return None;
                }

                let pk = hex::decode(pk_hex).ok()?;
                let message = hex::decode(msg_hex).ok()?;
                let signature = hex::decode(sig_hex).ok()?;

                Some(AcvpVector {
                    tc_id,
                    pk,
                    message,
                    signature,
                    expected,
                })
            })
            .collect()
    }

    #[test]
    fn acvp_sigver_vectors() {
        let vectors = load_acvp_vectors();

        if vectors.is_empty() {
            eprintln!(
                "\n╔══════════════════════════════════════════════════════════╗\n\
                 ║  ACVP vectors not yet vendored — test skipped.          ║\n\
                 ║  Replace placeholder in:                                ║\n\
                 ║  crates/mldsa44/tests/vectors/acvp_mldsa44_sigver.json ║\n\
                 ╚══════════════════════════════════════════════════════════╝\n"
            );
            return;
        }

        let mut pass = 0u32;
        let mut fail = 0u32;

        for v in &vectors {
            let result = verify_pk(&v.pk, &v.message, &v.signature);

            let got_pass = result.is_ok();

            if got_pass != v.expected {
                fail += 1;
                eprintln!(
                    "ACVP tcId={}: MISMATCH — expected={}, got={}  (err={:?})",
                    v.tc_id,
                    v.expected,
                    got_pass,
                    result.err()
                );
            } else {
                pass += 1;
            }
        }

        eprintln!("\nACVP ML-DSA-44 sigVer: {}/{} passed", pass, pass + fail);
        assert_eq!(fail, 0, "{} ACVP vector(s) failed", fail);
    }

    // ── Self-generated vectors (always run, validates liboqs integration) ──

    #[test]
    fn self_gen_sign_verify_accept() {
        // Generate keypair, sign a message, verify it accepts
        oqs::init();
        let scheme =
            oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa44).expect("ML-DSA-44 unavailable");

        let (pk, sk) = scheme.keypair().expect("keygen failed");

        // Test with several message lengths
        let messages: &[&[u8]] = &[
            b"",           // empty message
            b"A",          // 1 byte
            &[0x42u8; 64], // 64 bytes (μ-sized)
            &[0xAA; 1000], // 1000 bytes
        ];

        for (i, msg) in messages.iter().enumerate() {
            let sig = scheme.sign(msg, &sk).expect("sign failed");
            let result = verify_pk(pk.as_ref(), msg, sig.as_ref());
            assert!(
                result.is_ok(),
                "self-gen vector {} (msg len={}) should pass: {:?}",
                i,
                msg.len(),
                result
            );
        }
    }

    #[test]
    fn self_gen_tampered_sig_reject() {
        oqs::init();
        let scheme =
            oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa44).expect("ML-DSA-44 unavailable");

        let (pk, sk) = scheme.keypair().expect("keygen failed");
        let msg = [0x42u8; 64];
        let sig = scheme.sign(&msg, &sk).expect("sign failed");

        // Tamper: flip each of first 8 bytes independently
        for byte_idx in 0..8 {
            let mut tampered = sig.as_ref().to_vec();
            tampered[byte_idx] ^= 0xFF;
            assert_eq!(
                verify_pk(pk.as_ref(), &msg, &tampered),
                Err(MlDsa44Error::SignatureInvalid),
                "tampered byte {} should reject",
                byte_idx
            );
        }
    }

    #[test]
    fn self_gen_wrong_pk_reject() {
        oqs::init();
        let scheme =
            oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa44).expect("ML-DSA-44 unavailable");

        let (pk1, sk1) = scheme.keypair().expect("keygen 1 failed");
        let (pk2, _sk2) = scheme.keypair().expect("keygen 2 failed");

        let msg = b"cross-key test";
        let sig = scheme.sign(msg, &sk1).expect("sign failed");

        // Verify with wrong public key — must reject
        assert_eq!(
            verify_pk(pk2.as_ref(), msg, sig.as_ref()),
            Err(MlDsa44Error::SignatureInvalid),
            "wrong public key should reject"
        );

        // Verify with correct public key — must accept
        assert!(verify_pk(pk1.as_ref(), msg, sig.as_ref()).is_ok());
    }

    #[test]
    fn self_gen_verify_via_andna_pipeline_interface() {
        // Test through the AN-DNA interface: verify(rho, t1, mu, sig)
        use andna_contracts::{MU_LEN, TE_RHO_LEN, TE_T1_LEN};
        use andna_mldsa44::verify;

        oqs::init();
        let scheme =
            oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa44).expect("ML-DSA-44 unavailable");

        let (pk, sk) = scheme.keypair().expect("keygen failed");
        let pk_bytes = pk.as_ref();

        // μ is 64 bytes — this is the AN-DNA message
        let mu = [0xDE; MU_LEN];
        let signature = scheme.sign(&mu, &sk).expect("sign failed");

        // Split pk into rho/t1 per contracts layout
        let rho: &[u8; TE_RHO_LEN] = pk_bytes[..TE_RHO_LEN].try_into().unwrap();
        let t1: &[u8; TE_T1_LEN] = pk_bytes[TE_RHO_LEN..TE_RHO_LEN + TE_T1_LEN]
            .try_into()
            .unwrap();
        let sig_arr: &[u8; SIG_LEN] = signature.as_ref().try_into().unwrap();

        assert!(verify(rho, t1, &mu, sig_arr).is_ok());
    }

    #[test]
    fn liboqs_lengths_are_locked() {
        oqs::init();
        let scheme =
            oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa44).expect("ML-DSA-44 unavailable");

        assert_eq!(
            scheme.length_public_key(),
            ML_DSA_44_PK_LEN,
            "liboqs pk len drifted from contracts"
        );
        assert_eq!(
            scheme.length_signature(),
            SIG_LEN,
            "liboqs sig len drifted from contracts"
        );
    }
}
