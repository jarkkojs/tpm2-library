// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jarkko Sakkinen

//! Property tests. The population seed is printed by every test and can be
//! pinned with `TPM2_TEST_SEED` to reproduce a failing run.

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use proptest::{prelude::*, test_runner::RngSeed};
use std::{
    collections::{HashMap, HashSet, hash_map::RandomState},
    fs,
    hash::{BuildHasher, Hasher},
    sync::OnceLock,
};
use tempfile::tempdir;
use tpm2_crypto::tpm_make_name;
use tpm2_protocol::{
    TpmMarshal, TpmSized, TpmWriter,
    basic::{TpmHandle, TpmUint16, TpmUint64},
    data::{
        Tpm2b, Tpm2bDigest, Tpm2bName, Tpm2bPublicKeyRsa, TpmAlgId, TpmCc, TpmRh, TpmsContext,
        TpmsRsaParms, TpmtPublic, TpmuPublicId, TpmuPublicParms,
    },
};
use tpm2_vtpm::{VtpmCache, VtpmError, VtpmPolicyCommand, vtpm_policy_command_from_parts};

const SEED_VAR: &str = "TPM2_TEST_SEED";
const CASES: u32 = 1024;
const MAX_POLICY_COUNT: usize = 16;

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

fn marshal<T: TpmMarshal + TpmSized>(value: &T) -> Vec<u8> {
    let mut buf = vec![0; value.len()];
    let mut writer = TpmWriter::new(&mut buf);
    value.marshal(&mut writer).unwrap();
    buf
}

fn rsa_public(id: u16) -> TpmtPublic {
    let modulus = [id.to_be_bytes().as_slice(), &[0xa5; 30]].concat();
    TpmtPublic {
        object_type: TpmAlgId::Rsa,
        name_alg: TpmAlgId::Sha256,
        parameters: TpmuPublicParms::Rsa(TpmsRsaParms {
            key_bits: TpmUint16::new(2048),
            ..TpmsRsaParms::default()
        }),
        unique: TpmuPublicId::Rsa(Tpm2bPublicKeyRsa::try_from(modulus.as_slice()).unwrap()),
        ..TpmtPublic::default()
    }
}

fn null_public() -> TpmtPublic {
    TpmtPublic {
        object_type: TpmAlgId::Null,
        ..TpmtPublic::default()
    }
}

fn context_strategy() -> impl Strategy<Value = TpmsContext> {
    (
        any::<u64>(),
        any::<u32>(),
        prop::collection::vec(any::<u8>(), 0..=256),
    )
        .prop_map(|(sequence, saved, blob)| TpmsContext {
            sequence: TpmUint64::new(sequence),
            saved_handle: TpmHandle::new(saved),
            hierarchy: TpmRh::Owner,
            context_blob: Tpm2b::try_from(blob.as_slice()).unwrap(),
        })
}

/// Valid `(cc, body)` pairs for cached policy commands.
fn policy_part() -> impl Strategy<Value = (TpmCc, Vec<u8>)> {
    let digest = prop::collection::vec(any::<u8>(), 0..=64)
        .prop_map(|d| marshal(&Tpm2bDigest::try_from(d.as_slice()).unwrap()));
    prop_oneof![
        prop::sample::select(vec![
            TpmCc::PolicyAuthValue,
            TpmCc::PolicyPassword,
            TpmCc::PolicyGetDigest,
            TpmCc::PolicyRestart,
            TpmCc::PolicyPhysicalPresence,
        ])
        .prop_map(|cc| (cc, Vec::new())),
        (
            prop::sample::select(vec![
                TpmCc::PolicyCpHash,
                TpmCc::PolicyNameHash,
                TpmCc::PolicyTemplate,
            ]),
            digest.clone(),
        ),
        prop::sample::select(vec![TpmCc::Startup, TpmCc::PolicyPcr, TpmCc::Unseal])
            .prop_map(|code| (TpmCc::PolicyCommandCode, marshal(&code))),
        any::<bool>().prop_map(|set| (TpmCc::PolicyNvWritten, vec![u8::from(set)])),
        (
            any::<u32>(),
            prop::collection::vec(any::<u8>(), 0..=34),
            digest
        )
            .prop_map(|(hint, name, policy_ref)| {
                let mut body = hint.to_be_bytes().to_vec();
                body.extend(marshal(&Tpm2bName::try_from(name.as_slice()).unwrap()));
                body.extend(policy_ref);
                (TpmCc::PolicySecret, body)
            }),
    ]
}

fn policy_strategy(max: usize) -> impl Strategy<Value = Vec<Box<dyn VtpmPolicyCommand>>> {
    prop::collection::vec(policy_part(), 0..=max).prop_map(|parts| {
        parts
            .into_iter()
            .map(|(cc, body)| vtpm_policy_command_from_parts(cc, &body).unwrap())
            .collect()
    })
}

/// Parent selector for a generated key.
#[derive(Debug, Clone, Copy)]
enum Parent {
    Null,
    Key(usize),
    Persistent,
}

#[derive(Debug, Clone)]
struct Spec {
    parent: Parent,
    context: TpmsContext,
    policy: Vec<Box<dyn VtpmPolicyCommand>>,
}

/// A forest of keys whose parents always precede their children.
fn forest() -> impl Strategy<Value = Vec<Spec>> {
    prop::collection::vec(
        (
            any::<prop::sample::Index>(),
            0u8..8,
            context_strategy(),
            policy_strategy(4),
        ),
        1..8,
    )
    .prop_map(|items| {
        items
            .into_iter()
            .enumerate()
            .map(|(i, (index, kind, context, policy))| {
                let parent = match kind {
                    0 | 1 => Parent::Null,
                    2 => Parent::Persistent,
                    _ if i == 0 => Parent::Null,
                    _ => Parent::Key(index.index(i)),
                };
                Spec {
                    parent,
                    context,
                    policy,
                }
            })
            .collect()
    })
}

const PERSISTENT_ROOT: u32 = 0x8100_0001;

fn parent_public(spec: &Spec) -> TpmtPublic {
    match spec.parent {
        Parent::Null => null_public(),
        Parent::Key(parent) => rsa_public(u16::try_from(parent).unwrap()),
        Parent::Persistent => rsa_public(0xffff),
    }
}

fn physical_handles() -> HashMap<Tpm2bName, TpmHandle> {
    HashMap::from([(
        tpm_make_name(&rsa_public(0xffff)).unwrap(),
        TpmHandle::new(PERSISTENT_ROOT),
    )])
}

fn descendants(specs: &[Spec], root: usize) -> HashSet<usize> {
    let mut set = HashSet::from([root]);
    loop {
        let before = set.len();
        for (i, spec) in specs.iter().enumerate() {
            if let Parent::Key(parent) = spec.parent
                && set.contains(&parent)
            {
                set.insert(i);
            }
        }
        if set.len() == before {
            return set;
        }
    }
}

proptest! {
    #![proptest_config(config(CASES / 4))]

    #[test]
    fn cache_persists_and_resolves_keys(specs in forest(), remove in any::<prop::sample::Index>()) {
        let dir = tempdir().unwrap();
        let mut handles = Vec::new();
        {
            let mut cache = VtpmCache::new(dir.path(), physical_handles()).unwrap();
            for (i, spec) in specs.iter().enumerate() {
                let public = rsa_public(u16::try_from(i).unwrap());
                let handle = cache
                    .save_transient(spec.context.clone(), &public, &parent_public(spec), Some(&spec.policy))
                    .unwrap();
                prop_assert_eq!(handle.value() >> 24, 0x80);
                handles.push(handle);
            }
            cache.flush().unwrap();
        }

        let mut cache = VtpmCache::new(dir.path(), physical_handles()).unwrap();
        prop_assert_eq!(cache.key_iter().count(), specs.len());
        prop_assert_eq!(handles.iter().collect::<HashSet<_>>().len(), specs.len());

        for (i, spec) in specs.iter().enumerate() {
            let public = rsa_public(u16::try_from(i).unwrap());
            let key = cache.find_by_handle(handles[i]).unwrap();
            prop_assert_eq!(key.public(), &public);
            prop_assert_eq!(key.parent(), &parent_public(spec));
            prop_assert_eq!(key.context(), &spec.context);
            prop_assert_eq!(key.policy(), spec.policy.as_slice());

            let found = cache.find_by_name(&tpm_make_name(&public).unwrap()).unwrap();
            prop_assert_eq!(found.handle(), handles[i]);

            let mut expected = Vec::new();
            let mut current = i;
            loop {
                expected.insert(0, handles[current]);
                match specs[current].parent {
                    Parent::Key(parent) => current = parent,
                    Parent::Persistent => {
                        expected.insert(0, TpmHandle::new(PERSISTENT_ROOT));
                        break;
                    }
                    Parent::Null => break,
                }
            }
            prop_assert_eq!(cache.fetch_ancestors(handles[i]).unwrap(), expected);
        }

        let root = remove.index(specs.len());
        let expected: HashSet<TpmHandle> = descendants(&specs, root).into_iter().map(|i| handles[i]).collect();
        let deleted: HashSet<TpmHandle> = cache.remove(handles[root]).unwrap().into_iter().collect();
        prop_assert_eq!(&deleted, &expected);
        drop(cache);

        let cache = VtpmCache::new(dir.path(), physical_handles()).unwrap();
        let remaining: HashSet<TpmHandle> = cache.key_iter().map(|(h, _)| h).collect();
        let all: HashSet<TpmHandle> = handles.iter().copied().collect();
        prop_assert_eq!(remaining, all.difference(&expected).copied().collect::<HashSet<_>>());
        for handle in &expected {
            prop_assert!(cache.find_by_handle(*handle).is_none());
        }
    }

    #[test]
    fn fetch_ancestors_terminates_on_any_parent_graph(parents in prop::collection::vec(0u8..10, 1..6), unknown in any::<bool>()) {
        let dir = tempdir().unwrap();
        let mut cache = VtpmCache::new(dir.path(), physical_handles()).unwrap();
        let count = parents.len();
        let mut handles = Vec::new();
        for (i, parent) in parents.iter().enumerate() {
            let parent = match usize::from(*parent) {
                p if p < count => rsa_public(u16::try_from(p).unwrap()),
                p if p == count && unknown => rsa_public(0xfff0),
                p if p == count => rsa_public(0xffff),
                _ => null_public(),
            };
            let public = rsa_public(u16::try_from(i).unwrap());
            handles.push(cache.save_transient(TpmsContext {
                sequence: TpmUint64::new(0),
                saved_handle: TpmHandle::new(0),
                hierarchy: TpmRh::Owner,
                context_blob: Tpm2b::default(),
            }, &public, &parent, None).unwrap());
        }

        for handle in &handles {
            match cache.fetch_ancestors(*handle) {
                Ok(chain) => {
                    prop_assert_eq!(chain.last(), Some(handle));
                    let unique: HashSet<_> = chain.iter().collect();
                    prop_assert_eq!(unique.len(), chain.len());
                    for pair in chain.windows(2) {
                        if pair[0].value() == PERSISTENT_ROOT {
                            continue;
                        }
                        let parent = cache.find_by_handle(pair[0]).unwrap();
                        let child = cache.find_by_handle(pair[1]).unwrap();
                        prop_assert_eq!(child.parent(), parent.public());
                    }
                }
                Err(err) => prop_assert!(matches!(err, VtpmError::ParentNotFound), "{:?}", err),
            }
        }
    }

    #[test]
    fn cached_records_never_exceed_load_limits(policy in policy_strategy(MAX_POLICY_COUNT + 4), context in context_strategy(), persistent in any::<bool>()) {
        let dir = tempdir().unwrap();
        let public = rsa_public(1);
        let count = policy.len();
        let handle = {
            let mut cache = VtpmCache::new(dir.path(), HashMap::new()).unwrap();
            let result = if persistent {
                cache
                    .save_persistent(TpmHandle::new(PERSISTENT_ROOT), &public, &null_public(), Some(&policy))
                    .map(|()| TpmHandle::new(PERSISTENT_ROOT))
            } else {
                cache.save_transient(context, &public, &null_public(), Some(&policy))
            };
            if count > MAX_POLICY_COUNT {
                prop_assert!(matches!(result, Err(VtpmError::TooManyPolicies(n)) if n == count), "{:?}", result);
                prop_assert!(cache.key_iter().next().is_none());
                return Ok(());
            }
            let handle = result.unwrap();
            cache.flush().unwrap();
            handle
        };

        let cache = VtpmCache::new(dir.path(), HashMap::new()).unwrap();
        let key = cache.find_by_handle(handle).unwrap();
        prop_assert_eq!(key.policy(), policy.as_slice());
    }

    #[test]
    fn corrupt_records_are_discarded(specs in forest(), index in any::<prop::sample::Index>(), cut in any::<prop::sample::Index>(), noise in prop::collection::vec(any::<u8>(), 0..64)) {
        let dir = tempdir().unwrap();
        let mut handles = Vec::new();
        {
            let mut cache = VtpmCache::new(dir.path(), HashMap::new()).unwrap();
            for (i, spec) in specs.iter().enumerate() {
                let public = rsa_public(u16::try_from(i).unwrap());
                handles.push(
                    cache
                        .save_transient(spec.context.clone(), &public, &null_public(), Some(&spec.policy))
                        .unwrap(),
                );
            }
        }

        let victim = handles[index.index(handles.len())];
        let path = dir.path().join(format!("{:08x}.bin", victim.value()));
        let record = fs::read(&path).unwrap();
        let mut corrupt = record[..cut.index(record.len())].to_vec();
        if corrupt.is_empty() {
            corrupt = noise;
        }
        fs::write(&path, &corrupt).unwrap();
        fs::write(dir.path().join("02000000.bin"), b"session").unwrap();

        let cache = VtpmCache::new(dir.path(), HashMap::new()).unwrap();
        prop_assert!(cache.find_by_handle(victim).is_none());
        prop_assert!(!path.exists());
        prop_assert!(!dir.path().join("02000000.bin").exists());
        prop_assert_eq!(cache.key_iter().count(), handles.len() - 1);
    }
}

proptest! {
    #![proptest_config(config(CASES))]

    #[test]
    fn policy_parts_are_validated(cc in prop::sample::select(vec![
        TpmCc::PolicyAuthValue, TpmCc::PolicyRestart, TpmCc::PolicyCpHash, TpmCc::PolicyNvWritten,
        TpmCc::PolicyCommandCode, TpmCc::PolicySecret, TpmCc::PolicyOr, TpmCc::PolicyPcr,
        TpmCc::PolicyCounterTimer, TpmCc::Startup, TpmCc::PolicyLocality,
    ]), body in prop::collection::vec(any::<u8>(), 0..80), (valid_cc, valid_body) in policy_part()) {
        if let Ok(command) = vtpm_policy_command_from_parts(cc, &body) {
            prop_assert_eq!(command.cc(), cc);
            prop_assert_eq!(command.body(), body.clone());
            prop_assert_eq!(command.len(), 8 + body.len());
            if cc != TpmCc::PolicySecret {
                prop_assert!(command.to_command().is_ok());
            }
        }

        let command = vtpm_policy_command_from_parts(valid_cc, &valid_body).unwrap();
        prop_assert_eq!(command.body(), valid_body.clone());
        prop_assert_eq!(command.len(), 8 + valid_body.len());
        let command = command.to_command().unwrap();
        prop_assert_eq!(tpm2_protocol::frame::TpmFrame::cc(&command), valid_cc);
    }
}
