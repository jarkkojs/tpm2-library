// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jarkko Sakkinen

//! Dependency-free randomized test runner.
//!
//! Every test binary generates a population of [`POPULATION`] cases from a
//! single 64-bit seed. The seed is printed before the population is run and
//! can be pinned with the `TPM2_TEST_SEED` environment variable to reproduce
//! a failing run.

#![allow(dead_code)]

use std::io::IsTerminal;
use std::panic::{self, AssertUnwindSafe};
use std::time::{SystemTime, UNIX_EPOCH};

pub const POPULATION: usize = 1024;
pub const SEED_VAR: &str = "TPM2_TEST_SEED";

/// `SplitMix64` pseudo-random generator.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub fn u32(&mut self) -> u32 {
        (self.u64() >> 32) as u32
    }

    pub fn u16(&mut self) -> u16 {
        (self.u64() >> 48) as u16
    }

    pub fn u8(&mut self) -> u8 {
        (self.u64() >> 56) as u8
    }

    pub fn bool(&mut self) -> bool {
        self.u64() & 1 == 1
    }

    /// Returns `true` with the probability `1 / n`.
    pub fn one_in(&mut self, n: usize) -> bool {
        self.below(n) == 0
    }

    /// Returns a value in `0..n`.
    pub fn below(&mut self, n: usize) -> usize {
        assert!(n > 0, "empty range");
        (self.u64() % n as u64) as usize
    }

    /// Returns a value in `lo..=hi`.
    pub fn range(&mut self, lo: usize, hi: usize) -> usize {
        assert!(lo <= hi, "empty range");
        lo + self.below(hi - lo + 1)
    }

    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }

    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.u8()).collect()
    }
}

/// Reads the seed from `TPM2_TEST_SEED`, or derives a fresh one.
pub fn seed() -> u64 {
    match std::env::var(SEED_VAR) {
        Ok(value) => {
            parse_seed(&value).unwrap_or_else(|| panic!("{SEED_VAR}: invalid seed '{value}'"))
        }
        Err(_) => {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            let mut rng = Rng::new((nanos as u64) ^ (u64::from(std::process::id()) << 32));
            rng.u64()
        }
    }
}

fn parse_seed(value: &str) -> Option<u64> {
    let value = value.trim();
    match value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => value.parse().ok(),
    }
}

fn status(ok: bool) -> &'static str {
    match (ok, std::io::stdout().is_terminal()) {
        (true, true) => "\x1B[32mOK\x1B[0m",
        (true, false) => "OK",
        (false, true) => "\x1B[31mFAILED\x1B[0m",
        (false, false) => "FAILED",
    }
}

/// Runs a population of randomized cases and exits with a failure status if
/// any case panics.
///
/// Each case receives its own generator derived from the population seed and
/// the case index, so a failing case is identified by its index alone.
pub fn run(name: &str, case: impl Fn(&mut Rng)) {
    let seed = seed();
    println!("Test {name}: population {POPULATION}, seed {seed:#018x}");

    let mut failed = Vec::new();
    for index in 0..POPULATION {
        let mut rng = Rng::new(seed ^ (index as u64).wrapping_mul(0xd1b5_4a32_d192_ed03));
        if panic::catch_unwind(AssertUnwindSafe(|| case(&mut rng))).is_err() {
            eprintln!("{name}: case {index} failed");
            failed.push(index);
        }
    }

    println!("Test {name} ... {}", status(failed.is_empty()));
    if !failed.is_empty() {
        eprintln!(
            "{name}: {} of {POPULATION} cases failed; rerun with {SEED_VAR}={seed:#018x}",
            failed.len()
        );
        std::process::exit(1);
    }
}
