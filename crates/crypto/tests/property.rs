// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jarkko Sakkinen

//! Property tests. The population seed is printed by every test and can be
//! pinned with `TPM2_TEST_SEED` to reproduce a failing run.

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use openssl::{
    bn::BigNum,
    derive::Deriver,
    ec::{EcGroup, EcKey},
    hash::{MessageDigest, hash},
    md::Md,
    nid::Nid,
    pkey::{PKey, Private},
    pkey_ctx::PkeyCtx,
    rsa::{Padding, Rsa},
};
use proptest::{prelude::*, test_runner::RngSeed};
use std::{
    collections::hash_map::RandomState,
    hash::{BuildHasher, Hasher},
    str::FromStr,
    sync::OnceLock,
};
use tpm2_crypto::{
    TpmCryptoError, TpmEccExternalKey, TpmEllipticCurve, TpmExternalKey, TpmHash,
    TpmPublicTemplate, TpmRsaExternalKey, tpm_make_name,
};
use tpm2_protocol::{
    TpmMarshal, TpmSized, TpmUnmarshal, TpmWriter,
    basic::{TpmUint16, TpmUint32},
    data::{
        Tpm2bDigest, Tpm2bEccParameter, Tpm2bPublicKeyRsa, TpmAlgId, TpmEccCurve, TpmaObject,
        TpmsEccPoint, TpmtPublic, TpmtSymDefObject, TpmuPublicId, TpmuPublicParms,
    },
};

const SEED_VAR: &str = "TPM2_TEST_SEED";
const CASES: u32 = 1024;
const SENTINEL: u8 = 0xa5;

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

const HASHES: [TpmHash; 8] = [
    TpmHash::Sha1,
    TpmHash::Sha256,
    TpmHash::Sha384,
    TpmHash::Sha512,
    TpmHash::Sm3_256,
    TpmHash::Sha3_256,
    TpmHash::Sha3_384,
    TpmHash::Sha3_512,
];

const ALL_HASHES: [TpmHash; 10] = [
    TpmHash::Sha1,
    TpmHash::Sha256,
    TpmHash::Sha384,
    TpmHash::Sha512,
    TpmHash::Sm3_256,
    TpmHash::Sha3_256,
    TpmHash::Sha3_384,
    TpmHash::Sha3_512,
    TpmHash::Shake128,
    TpmHash::Shake256,
];

const CURVES: [TpmEllipticCurve; 13] = [
    TpmEllipticCurve::NistP192,
    TpmEllipticCurve::NistP224,
    TpmEllipticCurve::NistP256,
    TpmEllipticCurve::NistP384,
    TpmEllipticCurve::NistP521,
    TpmEllipticCurve::BnP256,
    TpmEllipticCurve::BnP638,
    TpmEllipticCurve::Sm2P256,
    TpmEllipticCurve::BpP256R1,
    TpmEllipticCurve::BpP384R1,
    TpmEllipticCurve::BpP512R1,
    TpmEllipticCurve::Curve25519,
    TpmEllipticCurve::Curve448,
];

/// Curves usable for ECDH with OpenSSL, with their coordinate sizes.
const ECDH_CURVES: [(TpmEllipticCurve, Nid, usize); 8] = [
    (TpmEllipticCurve::NistP192, Nid::X9_62_PRIME192V1, 24),
    (TpmEllipticCurve::NistP224, Nid::SECP224R1, 28),
    (TpmEllipticCurve::NistP256, Nid::X9_62_PRIME256V1, 32),
    (TpmEllipticCurve::NistP384, Nid::SECP384R1, 48),
    (TpmEllipticCurve::NistP521, Nid::SECP521R1, 66),
    (TpmEllipticCurve::BpP256R1, Nid::BRAINPOOL_P256R1, 32),
    (TpmEllipticCurve::BpP384R1, Nid::BRAINPOOL_P384R1, 48),
    (TpmEllipticCurve::BpP512R1, Nid::BRAINPOOL_P512R1, 64),
];

fn md(alg: TpmHash) -> MessageDigest {
    alg.into()
}

/// HMAC block sizes from FIPS 198-1, FIPS 202 and GB/T 32905.
fn block_size(alg: TpmHash) -> usize {
    match alg {
        TpmHash::Sha384 | TpmHash::Sha512 => 128,
        TpmHash::Sha3_256 => 136,
        TpmHash::Sha3_384 => 104,
        TpmHash::Sha3_512 => 72,
        _ => 64,
    }
}

fn reference_digest(alg: TpmHash, data: &[u8]) -> Vec<u8> {
    hash(md(alg), data).unwrap().to_vec()
}

fn reference_hmac(alg: TpmHash, key: &[u8], data: &[u8]) -> Vec<u8> {
    let block = block_size(alg);
    let mut key = if key.len() > block {
        reference_digest(alg, key)
    } else {
        key.to_vec()
    };
    key.resize(block, 0);
    let inner: Vec<u8> = key
        .iter()
        .map(|b| b ^ 0x36)
        .chain(data.iter().copied())
        .collect();
    let inner = reference_digest(alg, &inner);
    let outer: Vec<u8> = key.iter().map(|b| b ^ 0x5c).chain(inner).collect();
    reference_digest(alg, &outer)
}

fn terminated(label: &[u8]) -> Vec<u8> {
    let mut label = label.to_vec();
    if label.last() != Some(&0) {
        label.push(0);
    }
    label
}

/// `KDFa` as defined in TCG TPM 2.0 Part 1, section 11.4.10.2.
fn reference_kdfa(
    alg: TpmHash,
    key: &[u8],
    label: &[u8],
    context_u: &[u8],
    context_v: &[u8],
    bits: usize,
) -> Vec<u8> {
    let bytes = bits.div_ceil(8);
    let mut stream = Vec::new();
    let mut counter = 1u32;
    while stream.len() < bytes {
        let data = [
            &counter.to_be_bytes()[..],
            &terminated(label),
            context_u,
            context_v,
            &u32::try_from(bits).unwrap().to_be_bytes(),
        ]
        .concat();
        stream.extend(reference_hmac(alg, key, &data));
        counter += 1;
    }
    stream.truncate(bytes);
    stream
}

/// `KDFe` as defined in TCG TPM 2.0 Part 1, section 11.4.10.3.
fn reference_kdfe(
    alg: TpmHash,
    z: &[u8],
    label: &[u8],
    context_u: &[u8],
    context_v: &[u8],
    bits: usize,
) -> Vec<u8> {
    let bytes = bits.div_ceil(8);
    let mut stream = Vec::new();
    let mut counter = 1u32;
    while stream.len() < bytes {
        let data = [
            &counter.to_be_bytes()[..],
            z,
            &terminated(label),
            context_u,
            context_v,
        ]
        .concat();
        stream.extend(reference_digest(alg, &data));
        counter += 1;
    }
    stream.truncate(bytes);
    if !bits.is_multiple_of(8) {
        stream[0] &= (1u8 << (bits % 8)) - 1;
    }
    stream
}

fn marshal<T: TpmMarshal + TpmSized>(value: &T) -> Vec<u8> {
    let mut buf = vec![0; value.len()];
    let len = {
        let mut writer = TpmWriter::new(&mut buf);
        value.marshal(&mut writer).unwrap();
        writer.len()
    };
    assert_eq!(len, buf.len());
    buf
}

fn hash_strategy() -> impl Strategy<Value = TpmHash> {
    prop::sample::select(HASHES.to_vec())
}

fn bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=max)
}

fn label_strategy() -> impl Strategy<Value = Vec<u8>> {
    (bytes(16), any::<bool>()).prop_map(|(mut label, nul)| {
        if nul {
            label.push(0);
        }
        label
    })
}

fn template_strategy() -> impl Strategy<Value = TpmPublicTemplate> {
    let attributes = any::<u32>().prop_map(TpmaObject::from_bits_truncate);
    (hash_strategy(), attributes, bytes(64)).prop_map(|(name_alg, attributes, policy)| {
        TpmPublicTemplate::new()
            .with_name_alg(name_alg)
            .with_object_attributes(attributes)
            .with_auth_policy(Tpm2bDigest::try_from(policy.as_slice()).unwrap())
            .with_symmetric(TpmtSymDefObject::default())
    })
}

fn rsa_keys() -> &'static [PKey<Private>] {
    static KEYS: OnceLock<Vec<PKey<Private>>> = OnceLock::new();
    KEYS.get_or_init(|| {
        let e3 = BigNum::from_u32(3).unwrap();
        vec![
            PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap(),
            PKey::from_rsa(Rsa::generate_with_e(2048, &e3).unwrap()).unwrap(),
        ]
    })
}

fn ecc_keys() -> &'static [PKey<Private>] {
    static KEYS: OnceLock<Vec<PKey<Private>>> = OnceLock::new();
    KEYS.get_or_init(|| {
        ECDH_CURVES
            .iter()
            .map(|(_, nid, _)| {
                let group = EcGroup::from_curve_name(*nid).unwrap();
                PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
            })
            .collect()
    })
}

fn template_string_strategy() -> impl Strategy<Value = String> {
    let hash = prop::sample::select(ALL_HASHES.to_vec()).prop_map(|h| h.to_string());
    let curve = prop::sample::select(CURVES.to_vec()).prop_map(|c| c.to_string());
    let rsa_scheme = prop::sample::select(vec!["null", "rsassa", "rsapss", "rsaes", "oaep"]);
    let ecc_scheme = prop::sample::select(vec![
        "null",
        "ecdsa",
        "ecdh",
        "ecdaa",
        "ecschnorr",
        "sm2",
        "ecmqv",
    ]);
    let keyedhash = prop::sample::select(vec!["null", "xor", "hmac"]);
    let rsa_bits = prop_oneof![
        Just(0u16),
        prop::sample::select(vec![1024u16, 2048, 3072, 4096]),
        any::<u16>(),
    ];
    prop_oneof![
        (rsa_bits, hash.clone(), prop::option::of(rsa_scheme)).prop_map(|(bits, hash, scheme)| {
            match scheme {
                Some(scheme) => format!("rsa-{bits}:{hash}:{scheme}"),
                None => format!("rsa-{bits}:{hash}"),
            }
        }),
        (curve, hash.clone(), prop::option::of(ecc_scheme)).prop_map(|(curve, hash, scheme)| {
            match scheme {
                Some(scheme) => format!("ecc-{curve}:{hash}:{scheme}"),
                None => format!("ecc-{curve}:{hash}"),
            }
        }),
        (keyedhash, hash).prop_map(|(scheme, hash)| format!("keyedhash-{scheme}:{hash}")),
    ]
}

proptest! {
    #![proptest_config(config(CASES))]

    #[test]
    fn digest_matches_reference(alg in hash_strategy(), chunks in prop::collection::vec(bytes(64), 0..4), extra in 0usize..4) {
        let refs: Vec<&[u8]> = chunks.iter().map(Vec::as_slice).collect();
        let expected = reference_digest(alg, &chunks.concat());

        prop_assert_eq!(alg.size(), expected.len());
        prop_assert_eq!(&alg.digest(&refs).unwrap(), &expected);

        let mut output = vec![SENTINEL; alg.size() + extra];
        let len = alg.digest_into(&refs, &mut output).unwrap();
        prop_assert_eq!(&output[..len], expected.as_slice());
        prop_assert!(output[len..].iter().all(|b| *b == SENTINEL));

        let mut short = vec![0; alg.size() - 1 - extra.min(alg.size() - 1)];
        prop_assert_eq!(
            alg.digest_into(&refs, &mut short),
            Err(TpmCryptoError::BufferTooSmall { expected: alg.size(), actual: short.len() })
        );
    }

    #[test]
    fn hmac_matches_reference(alg in hash_strategy(), key in bytes(200), chunks in prop::collection::vec(bytes(64), 0..4), flip in any::<prop::sample::Index>()) {
        let refs: Vec<&[u8]> = chunks.iter().map(Vec::as_slice).collect();
        if key.is_empty() {
            prop_assert_eq!(alg.hmac(&key, &refs), Err(TpmCryptoError::KeyIsEmpty));
            return Ok(());
        }

        let expected = reference_hmac(alg, &key, &chunks.concat());
        let mac = alg.hmac(&key, &refs).unwrap();
        prop_assert_eq!(&mac, &expected);

        let mut output = vec![SENTINEL; mac.len() + 1];
        let len = alg.hmac_into(&key, &refs, &mut output).unwrap();
        prop_assert_eq!(&output[..len], mac.as_slice());
        prop_assert_eq!(output[len], SENTINEL);
        let mut short = vec![0; mac.len() - 1];
        prop_assert_eq!(
            alg.hmac_into(&key, &refs, &mut short),
            Err(TpmCryptoError::BufferTooSmall { expected: mac.len(), actual: mac.len() - 1 })
        );

        prop_assert_eq!(alg.hmac_verify(&key, &refs, &mac), Ok(()));
        let mut bad = mac.clone();
        let bit = flip.index(bad.len() * 8);
        bad[bit / 8] ^= 1 << (bit % 8);
        prop_assert_eq!(alg.hmac_verify(&key, &refs, &bad), Err(TpmCryptoError::MacMismatch));
        prop_assert_eq!(
            alg.hmac_verify(&key, &refs, &mac[..mac.len() - 1]),
            Err(TpmCryptoError::MacMismatch)
        );
    }

    #[test]
    fn kdfa_matches_reference(alg in hash_strategy(), key in bytes(64), label in label_strategy(), context_u in bytes(32), context_v in bytes(32), bits in 0usize..=1100) {
        if key.is_empty() {
            prop_assert_eq!(alg.kdfa(&key, &label, &context_u, &context_v, bits), Err(TpmCryptoError::KeyIsEmpty));
            return Ok(());
        }

        let expected = reference_kdfa(alg, &key, &label, &context_u, &context_v, bits);
        prop_assert_eq!(&alg.kdfa(&key, &label, &context_u, &context_v, bits).unwrap(), &expected);

        let mut output = vec![SENTINEL; expected.len() + 1];
        let len = alg.kdfa_into(&key, &label, &context_u, &context_v, bits, &mut output).unwrap();
        prop_assert_eq!(&output[..len], expected.as_slice());
        prop_assert_eq!(output[len], SENTINEL);

        if !expected.is_empty() {
            let mut short = vec![0; expected.len() - 1];
            prop_assert_eq!(
                alg.kdfa_into(&key, &label, &context_u, &context_v, bits, &mut short),
                Err(TpmCryptoError::BufferTooSmall { expected: expected.len(), actual: short.len() })
            );
        }

        let too_large = usize::try_from(u64::from(u32::MAX) + 1).unwrap() + bits;
        prop_assert_eq!(
            alg.kdfa(&key, &label, &context_u, &context_v, too_large),
            Err(TpmCryptoError::InvalidKdfKeyBits(too_large))
        );
    }

    #[test]
    fn kdfe_matches_reference(alg in hash_strategy(), z in bytes(66), label in label_strategy(), context_u in bytes(66), context_v in bytes(66), bits in 0usize..=1100) {
        let expected = reference_kdfe(alg, &z, &label, &context_u, &context_v, bits);
        prop_assert_eq!(&alg.kdfe(&z, &label, &context_u, &context_v, bits).unwrap(), &expected);

        let mut output = vec![SENTINEL; expected.len() + 1];
        let len = alg.kdfe_into(&z, &label, &context_u, &context_v, bits, &mut output).unwrap();
        prop_assert_eq!(&output[..len], expected.as_slice());
        prop_assert_eq!(output[len], SENTINEL);

        if !expected.is_empty() {
            let mut short = vec![0; expected.len() - 1];
            prop_assert_eq!(
                alg.kdfe_into(&z, &label, &context_u, &context_v, bits, &mut short),
                Err(TpmCryptoError::BufferTooSmall { expected: expected.len(), actual: short.len() })
            );
        }

        let too_large = usize::try_from(u64::from(u32::MAX) + 1).unwrap() + bits;
        prop_assert_eq!(
            alg.kdfe(&z, &label, &context_u, &context_v, too_large),
            Err(TpmCryptoError::InvalidKdfKeyBits(too_large))
        );
    }

    #[test]
    fn algorithm_conversions_round_trip(raw in any::<u16>(), hash_index in 0..ALL_HASHES.len(), curve_index in 0..CURVES.len()) {
        let alg = ALL_HASHES[hash_index];
        prop_assert_eq!(TpmHash::try_from(TpmAlgId::from(alg)), Ok(alg));
        prop_assert_eq!(TpmHash::from_str(&alg.to_string()).unwrap(), alg);

        if let Ok(id) = TpmAlgId::try_from(raw) {
            let expected = ALL_HASHES.iter().find(|h| TpmAlgId::from(**h) == id).copied();
            match TpmHash::try_from(id) {
                Ok(hash) => prop_assert_eq!(Some(hash), expected),
                Err(err) => {
                    prop_assert_eq!(err, TpmCryptoError::InvalidHash);
                    prop_assert_eq!(expected, None);
                }
            }
        }

        let curve = CURVES[curve_index];
        let id = TpmEccCurve::from(curve);
        prop_assert_eq!(TpmEllipticCurve::try_from(id), Ok(curve));
        prop_assert_eq!(TpmEllipticCurve::from_str(&curve.to_string()).unwrap(), curve);
        let ecdh = ECDH_CURVES.iter().find(|c| c.0 == curve);
        match Nid::try_from(curve) {
            Ok(nid) => {
                prop_assert_eq!(TpmEllipticCurve::try_from(nid), Ok(curve));
                if let Some(entry) = ecdh {
                    prop_assert_eq!(entry.1, nid);
                }
            }
            Err(err) => {
                prop_assert_eq!(err, TpmCryptoError::InvalidEccCurve(id));
                prop_assert!(ecdh.is_none());
            }
        }
    }

    #[test]
    fn template_strings_round_trip(input in template_string_strategy()) {
        if input.starts_with("rsa-0:") {
            prop_assert_eq!(TpmPublicTemplate::from_str(&input), Err(TpmCryptoError::InvalidKeyBits(0)));
            return Ok(());
        }
        let template = TpmPublicTemplate::from_str(&input).unwrap();
        let output = String::try_from(&template).unwrap();
        prop_assert_eq!(&output, &input);

        let public = TpmtPublic::try_from(&template).unwrap();
        prop_assert_eq!(public.object_type, template.object_type());
        prop_assert_eq!(public.name_alg, template.name_alg());
        let back = TpmPublicTemplate::try_from(&public).unwrap();
        prop_assert_eq!(&back, &template);
        prop_assert_eq!(String::try_from(&back).unwrap(), input);
    }

    #[test]
    fn template_parser_is_total(input in "[a-z0-9:-]{0,40}", prefix in prop::sample::select(vec!["", "rsa-", "ecc-", "keyedhash-"])) {
        let input = format!("{prefix}{input}");
        if let Ok(template) = TpmPublicTemplate::from_str(&input) {
            let output = String::try_from(&template).unwrap();
            prop_assert_eq!(TpmPublicTemplate::from_str(&output).unwrap(), template);
        }
    }

    #[test]
    fn rsa_try_new_validates_shape(bits in any::<u16>(), len in 0usize..=512, exponent in any::<u32>(), canonical in any::<bool>()) {
        let (bits, len) = if canonical {
            let bytes = len.max(1);
            (u16::try_from(bytes * 8).unwrap(), bytes)
        } else {
            (bits, len)
        };
        let modulus = Tpm2bPublicKeyRsa::try_from(vec![0xc3; len].as_slice()).unwrap();
        let result = TpmRsaExternalKey::try_new(modulus, TpmUint32::new(exponent), TpmUint16::new(bits));

        if bits == 0 || bits % 8 != 0 {
            prop_assert_eq!(result, Err(TpmCryptoError::InvalidKeyBits(bits)));
        } else if len != usize::from(bits / 8) {
            prop_assert_eq!(result, Err(TpmCryptoError::InvalidRsaModulus(vec![0xc3; len])));
        } else if exponent != 0 && (exponent < 3 || exponent % 2 == 0) {
            prop_assert_eq!(result, Err(TpmCryptoError::InvalidRsaExponent(TpmUint32::new(exponent))));
        } else {
            let key = result.unwrap();
            prop_assert_eq!(key.key_bits().value(), bits);
            prop_assert_eq!(key.exponent().value(), exponent);
        }
    }

    #[test]
    fn rsa_public_area_round_trips(bytes in 1usize..=512, exponent in prop::sample::select(vec![0u32, 3, 5, 17, 257, 0x0001_0003]), template in template_strategy(), seed_byte in any::<u8>()) {
        let modulus = Tpm2bPublicKeyRsa::try_from(vec![seed_byte | 0x80; bytes].as_slice()).unwrap();
        let bits = u16::try_from(bytes * 8).unwrap();
        let key = TpmRsaExternalKey::try_new(modulus, TpmUint32::new(exponent), TpmUint16::new(bits)).unwrap();
        let public = key.to_public(&template);

        prop_assert_eq!(public.object_type, TpmAlgId::Rsa);
        prop_assert_eq!(public.name_alg, template.name_alg());
        prop_assert_eq!(public.object_attributes, template.object_attributes());
        prop_assert_eq!(public.auth_policy, template.auth_policy());
        prop_assert_eq!(TpmRsaExternalKey::try_from(&public), Ok(key));

        let name_alg = TpmHash::try_from(public.name_alg).unwrap();
        let mut expected = public.name_alg.value().to_be_bytes().to_vec();
        expected.extend(reference_digest(name_alg, &marshal(&public)));
        prop_assert_eq!(tpm_make_name(&public).unwrap().to_vec(), expected);

        let mut ecc = public.clone();
        ecc.object_type = TpmAlgId::Ecc;
        prop_assert!(TpmRsaExternalKey::try_from(&ecc).is_err());
        prop_assert!(TpmEccExternalKey::try_from(&public).is_err());
    }

    #[test]
    fn ecc_try_new_validates_shape(curve_index in 0..CURVES.len(), x_len in 0usize..=66, y_len in 0usize..=66, canonical in any::<bool>()) {
        let curve = CURVES[curve_index];
        let size = ECDH_CURVES
            .iter()
            .find(|c| c.0 == curve)
            .map(|c| c.2)
            .or((curve == TpmEllipticCurve::Sm2P256).then_some(32));
        let (x_len, y_len) = match (canonical, size) {
            (true, Some(size)) => (size, size),
            _ => (x_len, y_len),
        };
        let point = TpmsEccPoint {
            x: Tpm2bEccParameter::try_from(vec![1; x_len].as_slice()).unwrap(),
            y: Tpm2bEccParameter::try_from(vec![2; y_len].as_slice()).unwrap(),
        };
        let result = TpmEccExternalKey::try_new(curve, point);

        match size {
            None => prop_assert_eq!(result, Err(TpmCryptoError::InvalidEccCurve(curve.into()))),
            Some(size) if x_len == size && y_len == size => {
                let key = result.unwrap();
                prop_assert_eq!(key.curve(), curve);
                prop_assert_eq!(key.unique(), &point);
            }
            Some(size) => prop_assert_eq!(
                result,
                Err(TpmCryptoError::InvalidEccPoint {
                    curve: curve.into(),
                    x_len,
                    y_len,
                    expected_len: size,
                })
            ),
        }
    }
}

proptest! {
    #![proptest_config(config(CASES / 4))]

    #[test]
    fn rsa_seed_decrypts_with_private_key(key_index in 0..2usize, alg in hash_strategy()) {
        let pkey = &rsa_keys()[key_index];
        let rsa = pkey.rsa().unwrap();
        let (key, sensitive) = TpmRsaExternalKey::from_der(&pkey.private_key_to_der().unwrap()).unwrap();

        prop_assert_eq!(key.public_key().to_vec(), rsa.n().to_vec());
        prop_assert_eq!(usize::from(key.key_bits().value()), rsa.size() as usize * 8);
        let e = rsa.e().to_vec();
        let e = e.iter().fold(0u32, |acc, b| (acc << 8) | u32::from(*b));
        prop_assert_eq!(key.exponent().value(), if e == 65537 { 0 } else { e });
        prop_assert_eq!(sensitive.to_vec(), rsa.p().unwrap().to_vec());

        let (seed, encrypted) = key.to_seed(alg).unwrap();
        prop_assert_eq!(seed.as_ref().len(), alg.size());
        prop_assert_eq!(encrypted.as_ref().len(), rsa.size() as usize);

        let oaep = Md::from_nid(md(alg).type_()).unwrap();
        let mut ctx = PkeyCtx::new(pkey).unwrap();
        ctx.decrypt_init().unwrap();
        ctx.set_rsa_padding(Padding::PKCS1_OAEP).unwrap();
        ctx.set_rsa_oaep_md(oaep).unwrap();
        ctx.set_rsa_mgf1_md(oaep).unwrap();
        ctx.set_rsa_oaep_label(b"DUPLICATE\0").unwrap();
        let mut decrypted = Vec::new();
        ctx.decrypt_to_vec(encrypted.as_ref(), &mut decrypted).unwrap();
        prop_assert_eq!(decrypted.as_slice(), seed.as_ref());
    }

    #[test]
    fn ecc_seed_derives_from_shared_secret(key_index in 0..ECDH_CURVES.len(), alg in hash_strategy(), template in template_strategy()) {
        let (curve, nid, size) = ECDH_CURVES[key_index];
        let pkey = &ecc_keys()[key_index];
        let ec = pkey.ec_key().unwrap();
        let (key, sensitive) = TpmEccExternalKey::from_der(&pkey.private_key_to_der().unwrap()).unwrap();

        prop_assert_eq!(key.curve(), curve);
        prop_assert_eq!(key.unique().x.as_ref().len(), size);
        prop_assert_eq!(key.unique().y.as_ref().len(), size);
        prop_assert_eq!(sensitive.to_vec(), ec.private_key().to_vec());

        let public = key.to_public(&template);
        prop_assert_eq!(public.object_type, TpmAlgId::Ecc);
        prop_assert!(matches!(public.parameters, TpmuPublicParms::Ecc(p) if p.curve_id == curve.into()));
        prop_assert!(matches!(public.unique, TpmuPublicId::Ecc(p) if p == *key.unique()));
        prop_assert_eq!(TpmEccExternalKey::try_from(&public), Ok(key.clone()));

        let (seed, secret) = key.to_seed(alg).unwrap();
        let (ephemeral, rest) = TpmsEccPoint::unmarshal(secret.as_ref()).unwrap();
        prop_assert!(rest.is_empty());
        prop_assert_eq!(ephemeral.x.as_ref().len(), size);
        prop_assert_eq!(ephemeral.y.as_ref().len(), size);

        let group = EcGroup::from_curve_name(nid).unwrap();
        let x = BigNum::from_slice(ephemeral.x.as_ref()).unwrap();
        let y = BigNum::from_slice(ephemeral.y.as_ref()).unwrap();
        let peer = EcKey::from_public_key_affine_coordinates(&group, &x, &y).unwrap();
        peer.check_key().unwrap();

        let peer = PKey::from_ec_key(peer).unwrap();
        let mut deriver = Deriver::new(pkey).unwrap();
        deriver.set_peer(&peer).unwrap();
        let z = deriver.derive_to_vec().unwrap();

        let expected = reference_kdfe(alg, &z, b"DUPLICATE", ephemeral.x.as_ref(), key.unique().x.as_ref(), alg.size() * 8);
        prop_assert_eq!(seed.as_ref(), expected.as_slice());
    }
}
