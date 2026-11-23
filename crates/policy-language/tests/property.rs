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
use tpm2_crypto::TpmHash;
use tpm2_policy_language::{TpmPolicyContext, TpmPolicyExpression};
use tpm2_protocol::{
    TpmMarshal, TpmSized, TpmWriter,
    basic::TpmHandle,
    data::{
        Tpm2bDigest, Tpm2bName, TpmAlgId, TpmCc, TpmRh, TpmlPcrSelection, TpmsPcrSelect,
        TpmsPcrSelection,
    },
    frame::{TpmCommandValue as TpmCommand, TpmFrame},
};

const SEED_VAR: &str = "TPM2_TEST_SEED";
const CASES: u32 = 1024;
const PCR_COUNT: usize = 24;
const BANKS: [TpmHash; 3] = [TpmHash::Sha1, TpmHash::Sha256, TpmHash::Sha384];
const PERMANENT: [TpmRh; 4] = [
    TpmRh::Owner,
    TpmRh::Endorsement,
    TpmRh::Platform,
    TpmRh::Lockout,
];

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

/// Generated policy context together with its raw contents.
#[derive(Debug, Clone)]
struct Fixture {
    names: Vec<(u32, Vec<u8>)>,
    pcrs: Vec<(TpmHash, Vec<Vec<u8>>)>,
}

impl Fixture {
    fn context(&self) -> TpmPolicyContext {
        let mut builder = TpmPolicyContext::builder();
        for (handle, name) in &self.names {
            builder = builder.with_name(*handle, Tpm2bName::try_from(name.as_slice()).unwrap());
        }
        for (alg, values) in &self.pcrs {
            let bank = values.iter().enumerate().map(|(index, value)| {
                (
                    u32::try_from(index).unwrap(),
                    Tpm2bDigest::try_from(value.as_slice()).unwrap(),
                )
            });
            builder = builder.with_pcr_bank((*alg).into(), bank);
        }
        builder.build().unwrap()
    }

    fn handles(&self) -> Vec<u32> {
        self.names
            .iter()
            .map(|(handle, _)| *handle)
            .chain(PERMANENT.iter().map(|rh| *rh as u32))
            .collect()
    }

    fn name(&self, handle: u32) -> Vec<u8> {
        self.names
            .iter()
            .find(|(h, _)| *h == handle)
            .map_or_else(|| handle.to_be_bytes().to_vec(), |(_, name)| name.clone())
    }

    fn pcr(&self, alg: TpmAlgId, index: usize) -> &[u8] {
        let bank = self
            .pcrs
            .iter()
            .find(|(a, _)| TpmAlgId::from(*a) == alg)
            .unwrap();
        &bank.1[index]
    }
}

fn fixture() -> impl Strategy<Value = Fixture> {
    let name = (prop::sample::select(BANKS.to_vec())).prop_flat_map(|alg| {
        prop::collection::vec(any::<u8>(), alg.size()).prop_map(move |digest| {
            let mut name = TpmAlgId::from(alg).value().to_be_bytes().to_vec();
            name.extend(digest);
            name
        })
    });
    let handle = (any::<bool>(), 0u32..0x0100_0000)
        .prop_map(|(persistent, low)| if persistent { 0x8100_0000 } else { 0x8000_0000 } | low);
    let names = prop::collection::vec((handle, name), 1..4);
    let pcrs: Vec<_> = BANKS
        .iter()
        .map(|alg| {
            let alg = *alg;
            prop::collection::vec(prop::collection::vec(any::<u8>(), alg.size()), PCR_COUNT)
                .prop_map(move |values| (alg, values))
        })
        .collect();
    (names, pcrs).prop_map(|(names, pcrs)| Fixture { names, pcrs })
}

fn selections() -> impl Strategy<Value = TpmlPcrSelection> {
    let selection = (
        prop::sample::select(BANKS.to_vec()),
        prop::collection::btree_set(0..PCR_COUNT, 1..5),
    )
        .prop_map(|(alg, indices)| {
            let mut select = [0u8; PCR_COUNT / 8];
            for index in indices {
                select[index / 8] |= 1 << (index % 8);
            }
            TpmsPcrSelection {
                hash: alg.into(),
                pcr_select: TpmsPcrSelect::try_from(select.as_slice()).unwrap(),
            }
        });
    prop::collection::vec(selection, 1..3).prop_map(|items| {
        let mut list = TpmlPcrSelection::new();
        for item in items {
            list.try_push(item).unwrap();
        }
        list
    })
}

fn leaf(
    handles: Vec<u32>,
    digest_size: usize,
    with_digest: bool,
) -> impl Strategy<Value = TpmPolicyExpression> {
    let digest = prop::collection::vec(any::<u8>(), digest_size)
        .prop_map(|d| Tpm2bDigest::try_from(d.as_slice()).unwrap());
    let digest = if with_digest {
        digest.prop_map(Some).boxed()
    } else {
        prop::option::of(digest).boxed()
    };
    let pcr = (selections(), digest)
        .prop_map(|(selections, digest)| TpmPolicyExpression::Pcr { selections, digest });
    let copy_ref = prop::option::of(
        prop::collection::vec(any::<u8>(), 1..=64)
            .prop_map(|d| Tpm2bDigest::try_from(d.as_slice()).unwrap()),
    );
    let secret = (prop::sample::select(handles), copy_ref).prop_map(|(handle, copy_ref)| {
        TpmPolicyExpression::Secret {
            auth_handle: Box::new(TpmPolicyExpression::Handle(TpmHandle::new(handle))),
            copy_ref,
        }
    });
    prop_oneof![pcr, secret]
}

/// Splices a leading term of the same kind, mirroring how the parser folds a
/// parenthesized left-hand side into the enclosing chain.
fn splice(mut terms: Vec<TpmPolicyExpression>, and: bool) -> Vec<TpmPolicyExpression> {
    match terms.first() {
        Some(TpmPolicyExpression::And(inner)) if and => {
            let mut spliced = inner.clone();
            spliced.extend(terms.drain(1..));
            spliced
        }
        Some(TpmPolicyExpression::Or(inner)) if !and => {
            let mut spliced = inner.clone();
            spliced.extend(terms.drain(1..));
            spliced
        }
        _ => terms,
    }
}

/// Arbitrary expressions, including ones where an OR follows other terms.
fn expression(handles: Vec<u32>, digest_size: usize) -> impl Strategy<Value = TpmPolicyExpression> {
    leaf(handles, digest_size, false).prop_recursive(3, 24, 3, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 2..=3)
                .prop_map(|terms| TpmPolicyExpression::And(splice(terms, true))),
            prop::collection::vec(inner, 2..=3)
                .prop_map(|terms| TpmPolicyExpression::Or(splice(terms, false))),
        ]
    })
}

/// Expressions in the form produced by `from_commands`: an OR may only start
/// an AND chain, chains are flat, and every PCR assertion carries a digest.
fn canonical(handles: Vec<u32>, digest_size: usize) -> impl Strategy<Value = TpmPolicyExpression> {
    let atom = leaf(handles.clone(), digest_size, true).boxed();
    leaf(handles, digest_size, true).prop_recursive(3, 24, 3, move |inner| {
        prop_oneof![
            (inner.clone(), prop::collection::vec(atom.clone(), 1..=2)).prop_map(
                |(head, atoms)| {
                    let mut terms = match head {
                        TpmPolicyExpression::And(terms) => terms,
                        head => vec![head],
                    };
                    terms.extend(atoms);
                    TpmPolicyExpression::And(terms)
                }
            ),
            prop::collection::vec(inner, 2..=3)
                .prop_map(|terms| TpmPolicyExpression::Or(splice(terms, false))),
        ]
    })
}

fn case(canonical_form: bool) -> impl Strategy<Value = (Fixture, TpmHash, TpmPolicyExpression)> {
    (fixture(), prop::sample::select(BANKS.to_vec())).prop_flat_map(move |(fixture, alg)| {
        let handles = fixture.handles();
        let expr = if canonical_form {
            canonical(handles, alg.size()).boxed()
        } else {
            expression(handles, alg.size()).boxed()
        };
        (Just(fixture), Just(alg), expr)
    })
}

fn extend(alg: TpmHash, chunks: &[&[u8]]) -> Vec<u8> {
    alg.digest(chunks).unwrap()
}

fn marshal_selections(selections: &TpmlPcrSelection) -> Vec<u8> {
    let mut buf = vec![0; selections.len()];
    let mut writer = TpmWriter::new(&mut buf);
    selections.marshal(&mut writer).unwrap();
    buf
}

fn policy_pcr(alg: TpmHash, digest: &[u8], selections: &TpmlPcrSelection, pcr: &[u8]) -> Vec<u8> {
    let cc = (TpmCc::PolicyPcr as u32).to_be_bytes();
    extend(alg, &[digest, &cc, &marshal_selections(selections), pcr])
}

fn policy_secret(alg: TpmHash, digest: &[u8], name: &[u8], policy_ref: &[u8]) -> Vec<u8> {
    let cc = (TpmCc::PolicySecret as u32).to_be_bytes();
    let digest = extend(alg, &[digest, &cc, name]);
    extend(alg, &[&digest, policy_ref])
}

fn policy_or(alg: TpmHash, branches: &[Vec<u8>]) -> Vec<u8> {
    let cc = (TpmCc::PolicyOr as u32).to_be_bytes();
    let zero = vec![0; alg.size()];
    extend(alg, &[&zero, &cc, &branches.concat()])
}

/// Policy digest of a canonical expression computed from the AST.
fn reference_digest(
    fixture: &Fixture,
    alg: TpmHash,
    expr: &TpmPolicyExpression,
    digest: Vec<u8>,
) -> Vec<u8> {
    match expr {
        TpmPolicyExpression::Pcr {
            selections,
            digest: pcr,
        } => policy_pcr(alg, &digest, selections, pcr.unwrap().as_ref()),
        TpmPolicyExpression::Secret {
            auth_handle,
            copy_ref,
        } => {
            let TpmPolicyExpression::Handle(handle) = **auth_handle else {
                panic!("secret without a handle");
            };
            let policy_ref = copy_ref.map(|r| r.to_vec()).unwrap_or_default();
            policy_secret(alg, &digest, &fixture.name(handle.value()), &policy_ref)
        }
        TpmPolicyExpression::And(terms) => terms.iter().fold(digest, |digest, term| {
            reference_digest(fixture, alg, term, digest)
        }),
        TpmPolicyExpression::Or(branches) => {
            assert!(digest.iter().all(|b| *b == 0), "OR after other assertions");
            let branches: Vec<Vec<u8>> = branches
                .iter()
                .map(|branch| reference_digest(fixture, alg, branch, vec![0; alg.size()]))
                .collect();
            policy_or(alg, &branches)
        }
        TpmPolicyExpression::Handle(_) => panic!("standalone handle"),
    }
}

/// Executes a command stream against a model policy session and returns the
/// final digest. Fails when an assertion is reset before an OR consumes it.
fn execute(fixture: &Fixture, alg: TpmHash, commands: &[TpmCommand]) -> Result<Vec<u8>, String> {
    let zero = vec![0; alg.size()];
    let mut digest = zero.clone();
    let mut stack: Vec<Vec<u8>> = Vec::new();

    for command in commands {
        match command {
            TpmCommand::PolicyRestart(_) => {
                stack.push(std::mem::replace(&mut digest, zero.clone()));
            }
            TpmCommand::PolicyPcr(cmd) => {
                digest = policy_pcr(alg, &digest, &cmd.pcrs, cmd.pcr_digest.as_ref());
            }
            TpmCommand::PolicySecret(cmd) => {
                let name = fixture.name(cmd.handles[0].value());
                digest = policy_secret(alg, &digest, &name, cmd.policy_ref.as_ref());
            }
            TpmCommand::PolicyOr(cmd) => {
                let count = cmd.p_hash_list.iter().count();
                if stack.len() < count {
                    return Err("OR without enough branches".into());
                }
                let mut branches = stack.split_off(stack.len() + 1 - count);
                branches.push(digest);
                let prefix = stack.pop().unwrap();
                if prefix != zero {
                    return Err("assertions before OR were discarded".into());
                }
                let listed: Vec<Vec<u8>> = cmd.p_hash_list.iter().map(|d| d.to_vec()).collect();
                if listed != branches {
                    return Err("OR digest list does not match its branches".into());
                }
                digest = policy_or(alg, &branches);
            }
            other => return Err(format!("unexpected command {:?}", other.cc())),
        }
    }

    if stack.is_empty() {
        Ok(digest)
    } else {
        Err("unbalanced branches".into())
    }
}

fn leaves(expr: &TpmPolicyExpression, out: &mut Vec<TpmPolicyExpression>) {
    match expr {
        TpmPolicyExpression::And(terms) | TpmPolicyExpression::Or(terms) => {
            for term in terms {
                leaves(term, out);
            }
        }
        leaf => out.push(leaf.clone()),
    }
}

proptest! {
    #![proptest_config(config(CASES))]

    #[test]
    fn display_and_parse_round_trip((fixture, _alg, expr) in case(false)) {
        let context = fixture.context();
        let text = expr.to_string();
        let parsed = TpmPolicyExpression::parse(&text, &context).unwrap();
        prop_assert_eq!(&parsed, &expr, "{}", text);
        prop_assert_eq!(parsed.to_string(), text);
    }

    #[test]
    fn canonical_policies_compile_and_round_trip((fixture, alg, expr) in case(true)) {
        let context = fixture.context();
        let compiled = expr.compile(alg.into(), &context).unwrap();
        let commands: Vec<TpmCommand> = compiled.commands().iter().map(|(c, _)| c.clone()).collect();

        prop_assert_eq!(&TpmPolicyExpression::from_commands(&commands).unwrap(), &expr);
        let expected = reference_digest(&fixture, alg, &expr, vec![0; alg.size()]);
        prop_assert_eq!(compiled.digest().to_vec(), expected.clone());
        prop_assert_eq!(execute(&fixture, alg, &commands), Ok(expected));
    }

    #[test]
    fn compiled_policies_enforce_every_assertion((fixture, alg, expr) in case(false)) {
        let context = fixture.context();
        let compiled = expr.compile(alg.into(), &context).unwrap();
        let commands: Vec<TpmCommand> = compiled.commands().iter().map(|(c, _)| c.clone()).collect();

        prop_assert_eq!(execute(&fixture, alg, &commands), Ok(compiled.digest().to_vec()));

        let rebuilt = TpmPolicyExpression::from_commands(&commands).unwrap();
        let recompiled = rebuilt.compile(alg.into(), &context).unwrap();
        prop_assert_eq!(&recompiled, &compiled);

        let mut expected = Vec::new();
        leaves(&expr, &mut expected);
        let mut actual = Vec::new();
        leaves(&rebuilt, &mut actual);
        for leaf in expected {
            let found = actual.iter().any(|candidate| match (&leaf, candidate) {
                (
                    TpmPolicyExpression::Pcr { selections, digest },
                    TpmPolicyExpression::Pcr { selections: s, digest: d },
                ) => selections == s && digest.is_none_or(|digest| Some(digest) == *d),
                (a, b) => a == b,
            });
            prop_assert!(found, "assertion {} dropped from {}", leaf, rebuilt);
        }
    }

    #[test]
    fn pcr_digest_is_computed_from_context(fixture in fixture(), alg in prop::sample::select(BANKS.to_vec()), selections in selections()) {
        let context = fixture.context();
        let expr = TpmPolicyExpression::Pcr { selections, digest: None };
        let compiled = expr.compile(alg.into(), &context).unwrap();
        let TpmCommand::PolicyPcr(cmd) = &compiled.commands()[0].0 else {
            panic!("expected PolicyPCR");
        };

        let mut values = Vec::new();
        for selection in selections.iter() {
            for index in 0..PCR_COUNT {
                if selection.pcr_select[index / 8] & (1 << (index % 8)) != 0 {
                    values.extend_from_slice(fixture.pcr(selection.hash, index));
                }
            }
        }
        prop_assert_eq!(cmd.pcr_digest.to_vec(), alg.digest(&[&values]).unwrap());
        prop_assert_eq!(cmd.pcrs, selections);
    }

    #[test]
    fn parser_is_total(fixture in fixture(), tokens in prop::collection::vec(prop::sample::select(vec![
        "pcr(", "secret(", "(", ")", ",", " and ", " or ", "sha256:", "sha1:0", "7", "+",
        "81000001", "40000001", "copy_ref:", "00", "ff", ":", "zz",
    ]), 0..16)) {
        let context = fixture.context();
        let text = tokens.concat();
        if let Ok(expr) = TpmPolicyExpression::parse(&text, &context) {
            prop_assert_eq!(TpmPolicyExpression::parse(&expr.to_string(), &context).unwrap(), expr);
        }
    }
}
