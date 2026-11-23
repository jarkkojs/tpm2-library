// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2026 Jarkko Sakkinen

#![allow(clippy::all)]
#![allow(clippy::pedantic)]

#[path = "common/random.rs"]
mod random;

use crate::random::Rng;
use std::convert::TryFrom;
use tpm2_protocol::{
    TpmError,
    data::{TpmRc, TpmRcBase, TpmRcFmt1, TpmRcIndex},
};

const FMT1: u32 = 0x080;
const P_BIT: u32 = 0x040;
const WARN: u32 = 0x900;
const FMT1_DEFINED_BITS: u32 = 0xfff;

/// Response codes and their renderings as given by the TCG specification.
const VECTORS: &[(u32, &str)] = &[
    (0x0000, "TPM_RC_SUCCESS"),
    (0x001e, "TPM_RC_BAD_TAG"),
    (0x0100, "TPM_RC_INITIALIZE"),
    (0x0101, "TPM_RC_FAILURE"),
    (0x0084, "TPM_RC_VALUE"),
    (0x018b, "[TPM_RC_HANDLE, handle[1]]"),
    (0x0482, "[TPM_RC_ATTRIBUTES, handle[4]]"),
    (0x01c4, "[TPM_RC_VALUE, parameter[1]]"),
    (0x02d5, "[TPM_RC_SIZE, parameter[2]]"),
    (0x088e, "[TPM_RC_AUTH_FAIL, session[0]]"),
    (0x098e, "[TPM_RC_AUTH_FAIL, session[1]]"),
    (0x09a2, "[TPM_RC_BAD_AUTH, session[1]]"),
    (0x0902, "TPM_RC_OBJECT_MEMORY"),
    (0x0922, "TPM_RC_RETRY"),
    (0x0923, "TPM_RC_NV_UNAVAILABLE"),
];

/// Response codes that the TCG specification does not define.
const INVALID: &[u32] = &[
    0x0040,
    0x00c0,
    0x0800,
    0x0880 | 0x3f,
    0x1000_0084,
    0xffff_ffff,
];

struct Bases {
    fmt0: Vec<(u32, TpmRcBase)>,
    fmt1: Vec<(u32, TpmRcBase)>,
}

fn discover() -> Bases {
    let mut fmt0 = Vec::new();
    let mut fmt1 = Vec::new();
    for raw in 0..=FMT1_DEFINED_BITS {
        let Ok(base) = TpmRcBase::try_from(raw) else {
            continue;
        };
        assert_eq!(base.value(), raw);
        assert!(base.to_string().starts_with("TPM_RC_"), "{raw:#x}: {base}");
        if raw & FMT1 != 0 {
            assert_eq!(raw & !(FMT1 | 0x3f), 0, "{raw:#x}: malformed format-1 base");
            fmt1.push((raw, base));
        } else {
            fmt0.push((raw, base));
        }
    }
    assert!(fmt0.len() > 32 && fmt1.len() > 32);
    Bases { fmt0, fmt1 }
}

/// Decodes `raw` from first principles of the TCG specification.
fn oracle(raw: u32) -> Option<(TpmRc, String)> {
    if raw & FMT1 == 0 {
        let base = TpmRcBase::try_from(raw).ok()?;
        let rc = if raw & WARN == WARN {
            TpmRc::Warn(base)
        } else {
            TpmRc::Fmt0(base)
        };
        return Some((rc, base.to_string()));
    }

    if raw & !FMT1_DEFINED_BITS != 0 {
        return None;
    }

    let base = TpmRcBase::try_from(FMT1 | (raw & 0x3f)).ok()?;
    let n = ((raw >> 8) & 0xf) as u8;
    let index = match (raw & P_BIT != 0, n) {
        (true, 0) => return None,
        (false, 0) => None,
        (true, n) => Some(TpmRcIndex::Parameter(n)),
        (false, n @ 1..=7) => Some(TpmRcIndex::Handle(n)),
        (false, n) => Some(TpmRcIndex::Session(n - 8)),
    };
    let text = match index {
        None => base.to_string(),
        Some(TpmRcIndex::Parameter(n)) => format!("[{base}, parameter[{n}]]"),
        Some(TpmRcIndex::Handle(n)) => format!("[{base}, handle[{n}]]"),
        Some(TpmRcIndex::Session(n)) => format!("[{base}, session[{n}]]"),
    };
    Some((TpmRc::Fmt1(TpmRcFmt1 { base, index }), text))
}

fn check(raw: u32) {
    let actual = TpmRc::try_from(raw);
    match oracle(raw) {
        Some((rc, text)) => {
            let actual = actual.unwrap_or_else(|e| panic!("{raw:#010x}: {e:?}"));
            assert_eq!(actual, rc, "{raw:#010x}");
            assert_eq!(actual.value(), raw, "{raw:#010x}");
            assert_eq!(actual.to_string(), text, "{raw:#010x}");
            let base = match rc {
                TpmRc::Fmt0(base) | TpmRc::Warn(base) => base,
                TpmRc::Fmt1(fmt1) => fmt1.base,
            };
            assert_eq!(actual.base(), base, "{raw:#010x}");
        }
        None => assert_eq!(
            actual,
            Err(TpmError::InvalidRc {
                offset: 0,
                value: u64::from(raw),
            }),
            "{raw:#010x}"
        ),
    }
}

fn vector(rng: &mut Rng) {
    let &(raw, text) = rng.pick(VECTORS);
    let rc = TpmRc::try_from(raw).unwrap_or_else(|e| panic!("{raw:#06x}: {e:?}"));
    assert_eq!(rc.to_string(), text, "{raw:#06x}");
    check(raw);

    let raw = *rng.pick(INVALID);
    assert!(TpmRc::try_from(raw).is_err(), "{raw:#010x}");
    check(raw);
}

fn format1(rng: &mut Rng, bases: &Bases) {
    let (base, _) = *rng.pick(&bases.fmt1);
    let mut raw = base | (u32::from(rng.u8() & 0x0f) << 8);
    if rng.bool() {
        raw |= P_BIT;
    }
    if rng.one_in(8) {
        raw ^= 1 << rng.range(12, 31);
    }
    if rng.one_in(8) {
        raw = FMT1 | (raw & !0x3f) | rng.below(0x40) as u32;
    }
    check(raw);
}

fn format0(rng: &mut Rng, bases: &Bases) {
    let raw = match rng.below(4) {
        0 => rng.pick(&bases.fmt0).0,
        1 => 0x100 | rng.below(0x80) as u32,
        2 => WARN | rng.below(0x80) as u32,
        _ => rng.pick(&bases.fmt0).0 ^ (1 << rng.below(32)),
    };
    check(raw);
}

fn noise(rng: &mut Rng) {
    let raw = match rng.below(3) {
        0 => rng.u32(),
        1 => rng.u32() & 0xfff,
        _ => rng.u32() & 0xffff,
    };
    check(raw);
}

fn construct(rng: &mut Rng, bases: &Bases) {
    let rc = match rng.below(3) {
        0 => {
            let (raw, base) = *rng.pick(&bases.fmt0);
            if raw & WARN == WARN {
                TpmRc::Warn(base)
            } else {
                TpmRc::Fmt0(base)
            }
        }
        _ => {
            let (_, base) = *rng.pick(&bases.fmt1);
            let index = match rng.below(4) {
                0 => None,
                1 => Some(TpmRcIndex::Parameter(rng.range(1, 15) as u8)),
                2 => Some(TpmRcIndex::Handle(rng.range(1, 7) as u8)),
                _ => Some(TpmRcIndex::Session(rng.range(0, 7) as u8)),
            };
            TpmRc::Fmt1(TpmRcFmt1 { base, index })
        }
    };
    let decoded = TpmRc::try_from(rc.value()).unwrap_or_else(|e| panic!("{rc:?}: {e:?}"));
    assert_eq!(decoded, rc);
    check(rc.value());
}

fn main() {
    let bases = discover();
    random::run("return_code", |rng| match rng.below(5) {
        0 => vector(rng),
        1 => format1(rng, &bases),
        2 => format0(rng, &bases),
        3 => noise(rng),
        _ => construct(rng, &bases),
    });
}
