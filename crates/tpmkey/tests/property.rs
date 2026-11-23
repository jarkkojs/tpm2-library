// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jarkko Sakkinen

//! Property tests. The population seed is printed by every test and can be
//! pinned with `TPM2_TEST_SEED` to reproduce a failing run.

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use proptest::{prelude::*, test_runner::RngSeed};
use std::{
    collections::hash_map::RandomState,
    hash::{BuildHasher, Hasher},
    sync::OnceLock,
};
use tpm2_protocol::{
    TpmMarshal, TpmSized, TpmWriter,
    basic::{TpmHandle, TpmUint16},
    constant::{MAX_PRIVATE_SIZE, MAX_RSA_KEY_BYTES},
    data::{
        Tpm2bDigest, Tpm2bEccParameter, Tpm2bEncryptedSecret, Tpm2bPrivate, Tpm2bPublic,
        Tpm2bPublicKeyRsa, Tpm2bPublicWire, TpmAlgId, TpmCc, TpmEccCurve, TpmsEccParms,
        TpmsEccPoint, TpmsKeyedhashParms, TpmsRsaParms, TpmtPublic, TpmuPublicId, TpmuPublicParms,
    },
};
use tpm2_tpmkey::{TpmKeyAuthPolicy, TpmKeyError, TpmKeyFile, TpmKeyPolicyCommand, TpmKeyType};

const SEED_VAR: &str = "TPM2_TEST_SEED";
const CASES: u32 = 1024;

fn seed() -> u64 {
    static SEED: OnceLock<u64> = OnceLock::new();
    *SEED.get_or_init(|| match std::env::var(SEED_VAR) {
        Ok(value) => {
            let value = value.trim();
            value
                .strip_prefix("0x")
                .map_or_else(
                    || value.parse().ok(),
                    |hex| u64::from_str_radix(hex, 16).ok(),
                )
                .unwrap_or_else(|| panic!("{SEED_VAR}: invalid seed '{value}'"))
        }
        Err(_) => RandomState::new().build_hasher().finish(),
    })
}

fn config(cases: u32) -> ProptestConfig {
    let seed = seed();
    eprintln!("population {cases}, seed {seed:#018x} (rerun with {SEED_VAR}={seed:#018x})");
    ProptestConfig {
        cases,
        rng_seed: RngSeed::Fixed(seed),
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

/// Policy command codes accepted by the TPMKEY policy encoding.
const POLICY_CC: [TpmCc; 25] = [
    TpmCc::PolicyNv,
    TpmCc::PolicySecret,
    TpmCc::PolicySigned,
    TpmCc::PolicyAuthorize,
    TpmCc::PolicyAuthValue,
    TpmCc::PolicyCommandCode,
    TpmCc::PolicyCounterTimer,
    TpmCc::PolicyCpHash,
    TpmCc::PolicyLocality,
    TpmCc::PolicyNameHash,
    TpmCc::PolicyOr,
    TpmCc::PolicyTicket,
    TpmCc::PolicyPcr,
    TpmCc::PolicyRestart,
    TpmCc::PolicyPhysicalPresence,
    TpmCc::PolicyDuplicationSelect,
    TpmCc::PolicyGetDigest,
    TpmCc::PolicyPassword,
    TpmCc::PolicyNvWritten,
    TpmCc::PolicyTemplate,
    TpmCc::PolicyAuthorizeNv,
    TpmCc::PolicyAcSendSelect,
    TpmCc::PolicyCapability,
    TpmCc::PolicyParameters,
    TpmCc::PolicyTransportSpdm,
];

const OTHER_CC: [TpmCc; 6] = [
    TpmCc::Startup,
    TpmCc::SelfTest,
    TpmCc::Create,
    TpmCc::Load,
    TpmCc::Unseal,
    TpmCc::GetRandom,
];

fn bytes(range: std::ops::RangeInclusive<usize>) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), range)
}

fn public(alg: TpmAlgId) -> impl Strategy<Value = TpmtPublic> {
    (bytes(0..=MAX_RSA_KEY_BYTES), bytes(0..=66), bytes(0..=64)).prop_map(move |(rsa, x, y)| {
        let (parameters, unique) = match alg {
            TpmAlgId::Rsa => (
                TpmuPublicParms::Rsa(TpmsRsaParms {
                    key_bits: TpmUint16::new(2048),
                    ..TpmsRsaParms::default()
                }),
                TpmuPublicId::Rsa(Tpm2bPublicKeyRsa::try_from(rsa.as_slice()).unwrap()),
            ),
            TpmAlgId::Ecc => (
                TpmuPublicParms::Ecc(TpmsEccParms {
                    curve_id: TpmEccCurve::NistP256,
                    ..TpmsEccParms::default()
                }),
                TpmuPublicId::Ecc(TpmsEccPoint {
                    x: Tpm2bEccParameter::try_from(x.as_slice()).unwrap(),
                    y: Tpm2bEccParameter::try_from(&y[..y.len().min(66)]).unwrap(),
                }),
            ),
            _ => (
                TpmuPublicParms::KeyedHash(TpmsKeyedhashParms::default()),
                TpmuPublicId::KeyedHash(Tpm2bDigest::try_from(y.as_slice()).unwrap()),
            ),
        };
        TpmtPublic {
            object_type: alg,
            name_alg: TpmAlgId::Sha256,
            parameters,
            unique,
            ..TpmtPublic::default()
        }
    })
}

fn policy(codes: &'static [TpmCc]) -> impl Strategy<Value = Vec<TpmKeyPolicyCommand>> {
    prop::collection::vec(
        (prop::sample::select(codes), bytes(0..=64))
            .prop_map(|(cc, body)| TpmKeyPolicyCommand::new(cc, body)),
        0..4,
    )
}

fn auth_policy() -> impl Strategy<Value = Vec<TpmKeyAuthPolicy>> {
    prop::collection::vec(
        (prop::option::of(".{0,16}"), policy(&POLICY_CC))
            .prop_map(|(name, policy)| TpmKeyAuthPolicy::new(name, policy)),
        0..3,
    )
}

fn key() -> impl Strategy<Value = TpmKeyFile> {
    let kind = prop::sample::select(vec![
        TpmKeyType::Loadable,
        TpmKeyType::Importable,
        TpmKeyType::SealedData,
    ]);
    kind.prop_flat_map(|kind| {
        let algs = match kind {
            TpmKeyType::SealedData => vec![TpmAlgId::KeyedHash],
            _ => vec![TpmAlgId::Rsa, TpmAlgId::Ecc, TpmAlgId::KeyedHash],
        };
        let public = prop::sample::select(algs).prop_flat_map(public);
        let secret = match kind {
            TpmKeyType::Loadable => Just(None).boxed(),
            TpmKeyType::Importable => bytes(1..=MAX_RSA_KEY_BYTES).prop_map(Some).boxed(),
            _ => prop::option::of(bytes(1..=MAX_RSA_KEY_BYTES)).boxed(),
        };
        let parent = (any::<bool>(), any::<u32>()).prop_map(|(rsa_parent, handle)| {
            if rsa_parent {
                (true, 0x4000_0000 | (handle & 0x00ff_ffff))
            } else {
                (false, handle)
            }
        });
        (
            Just(kind),
            public,
            bytes(0..=MAX_PRIVATE_SIZE),
            secret,
            policy(&POLICY_CC),
            auth_policy(),
            ".{0,32}",
            any::<bool>(),
            parent,
        )
    })
    .prop_map(
        |(kind, public, private, secret, policy, auth_policy, description, empty_auth, parent)| {
            let mut key = TpmKeyFile::new()
                .with_kind(kind)
                .with_public(Tpm2bPublic::from(public))
                .with_private(Tpm2bPrivate::try_from(private.as_slice()).unwrap())
                .with_policy(&policy)
                .with_auth_policy(auth_policy)
                .with_description(description)
                .with_empty_auth(empty_auth)
                .with_rsa_parent(parent.0)
                .with_parent(TpmHandle::new(parent.1));
            if let Some(secret) = secret {
                key = key.with_secret(&Tpm2bEncryptedSecret::try_from(secret.as_slice()).unwrap());
            }
            key
        },
    )
}

fn marshal<T: TpmMarshal + TpmSized>(value: &T) -> Vec<u8> {
    let mut buf = vec![0; value.len()];
    let mut writer = TpmWriter::new(&mut buf);
    value.marshal(&mut writer).unwrap();
    buf
}

proptest! {
    #![proptest_config(config(CASES))]

    #[test]
    fn keys_round_trip_through_der_and_pem(key in key()) {
        let der = key.to_der().unwrap();
        let decoded = TpmKeyFile::from_der(&der).unwrap();
        prop_assert_eq!(&decoded, &key);
        prop_assert_eq!(decoded.to_der().unwrap(), der);

        let pem = key.to_pem().unwrap();
        prop_assert!(pem.starts_with("-----BEGIN TSS2 PRIVATE KEY-----\n"));
        prop_assert_eq!(&TpmKeyFile::from_pem(pem.as_bytes()).unwrap(), &key);

        let public = Tpm2bPublicWire::cast(key.public()).unwrap();
        prop_assert_eq!(public.inner().unwrap().object_type, key.public_alg());
    }

    #[test]
    fn decoder_is_total(key in key(), index in any::<prop::sample::Index>(), value in any::<u8>(), cut in any::<prop::sample::Index>()) {
        let der = key.to_der().unwrap();

        let mut corrupt = der.clone();
        let i = index.index(corrupt.len());
        corrupt[i] = value;
        let truncated = &der[..cut.index(der.len())];

        for input in [corrupt.as_slice(), truncated] {
            if let Ok(decoded) = TpmKeyFile::from_der(input) {
                let reencoded = decoded.to_der().unwrap();
                prop_assert_eq!(TpmKeyFile::from_der(&reencoded).unwrap(), decoded);
            }
        }
        prop_assert!(TpmKeyFile::from_der(truncated).is_err());
    }

    #[test]
    fn secret_constraints_follow_key_type(key in key(), secret in bytes(1..=MAX_RSA_KEY_BYTES)) {
        let secret = Tpm2bEncryptedSecret::try_from(secret.as_slice()).unwrap();
        let with_secret = key.clone().with_secret(&secret);
        prop_assert_eq!(with_secret.secret().to_vec(), marshal(&secret));

        if key.kind() == TpmKeyType::Loadable {
            prop_assert!(matches!(with_secret.to_der(), Err(TpmKeyError::UnexpectedSecret)));
        } else {
            let decoded = TpmKeyFile::from_der(&with_secret.to_der().unwrap()).unwrap();
            prop_assert_eq!(decoded.secret(), with_secret.secret());
        }

        if key.kind() == TpmKeyType::Importable {
            let without = TpmKeyFile::new()
                .with_kind(TpmKeyType::Importable)
                .with_public(Tpm2bPublic::default());
            prop_assert!(matches!(without.to_der(), Err(TpmKeyError::MissingSecret)));
        }
    }

    #[test]
    fn rsa_parent_requires_permanent_handle(key in key(), handle in any::<u32>()) {
        let key = key.with_rsa_parent(true).with_parent(TpmHandle::new(handle));
        if handle >> 24 == 0x40 {
            prop_assert!(key.to_der().is_ok());
        } else {
            prop_assert!(matches!(key.to_der(), Err(TpmKeyError::InvalidPolicy)));
        }
    }

    #[test]
    fn encoder_and_decoder_agree_on_policy_codes(key in key(), policy in policy(&OTHER_CC), branch in any::<bool>()) {
        prop_assume!(!policy.is_empty());
        let key = if branch {
            key.with_auth_policy(vec![TpmKeyAuthPolicy::new(None, policy.clone())])
        } else {
            key.with_policy(&policy)
        };

        let cc = policy[0].cc();
        prop_assert!(matches!(key.to_der(), Err(TpmKeyError::InvalidCc(code)) if code == cc as u32));
    }

    #[test]
    fn public_and_private_bytes_are_validated(data in bytes(0..=96), public in public(TpmAlgId::KeyedHash)) {
        let expected_public = Tpm2bPublicWire::cast(&data).and_then(|wire| wire.inner().map(|p| p.object_type));
        match TpmKeyFile::new().with_public_bytes(&data) {
            Ok(key) => {
                prop_assert_eq!(key.public(), data.as_slice());
                prop_assert_eq!(Ok(key.public_alg()), expected_public);
            }
            Err(TpmKeyError::Unmarshal(err)) => prop_assert_eq!(Err(err), expected_public),
            Err(err) => prop_assert!(false, "unexpected error {:?}", err),
        }

        let encoded = marshal(&Tpm2bPublic::from(public));
        let key = TpmKeyFile::new().with_public_bytes(&encoded).unwrap();
        prop_assert_eq!(key.public_alg(), TpmAlgId::KeyedHash);

        let declared = data.first_chunk::<2>().map(|size| usize::from(u16::from_be_bytes(*size)));
        let valid_private = declared.is_some_and(|size| size <= MAX_PRIVATE_SIZE && size + 2 == data.len());
        prop_assert_eq!(TpmKeyFile::new().with_private_bytes(&data).is_ok(), valid_private);
    }
}
