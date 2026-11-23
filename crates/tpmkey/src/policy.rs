// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{TpmKeyError, asn1::TpmKeyCommandAsn1};
use tpm2_protocol::data::TpmCc;

/// A TPM policy command blob encoded according to the ASN.1 specification
/// encoding rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmKeyPolicyCommand {
    cc: TpmCc,
    body: Vec<u8>,
}

impl TpmKeyPolicyCommand {
    #[must_use]
    pub const fn new(cc: TpmCc, body: Vec<u8>) -> Self {
        TpmKeyPolicyCommand { cc, body }
    }

    #[must_use]
    pub const fn cc(&self) -> TpmCc {
        self.cc
    }

    #[must_use]
    pub const fn body(&self) -> &Vec<u8> {
        &self.body
    }
}

/// A TPM key policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmKeyAuthPolicy {
    name: Option<String>,
    policy: Vec<TpmKeyPolicyCommand>,
}

impl TpmKeyAuthPolicy {
    #[must_use]
    pub const fn new(name: Option<String>, policy: Vec<TpmKeyPolicyCommand>) -> Self {
        TpmKeyAuthPolicy { name, policy }
    }

    #[must_use]
    pub const fn empty() -> Self {
        TpmKeyAuthPolicy {
            name: None,
            policy: Vec::new(),
        }
    }

    #[must_use]
    pub const fn name(&self) -> &Option<String> {
        &self.name
    }

    #[must_use]
    pub const fn policy(&self) -> &Vec<TpmKeyPolicyCommand> {
        &self.policy
    }
    #[must_use]
    pub fn len(&self) -> usize {
        self.policy.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.policy.is_empty()
    }
}

impl Default for TpmKeyAuthPolicy {
    fn default() -> Self {
        Self::empty()
    }
}

impl TryFrom<&TpmKeyCommandAsn1> for TpmKeyPolicyCommand {
    type Error = TpmKeyError;

    fn try_from(val: &TpmKeyCommandAsn1) -> Result<Self, Self::Error> {
        let cc = TpmCc::try_from(val.command_code)
            .map_err(|_| TpmKeyError::InvalidCc(val.command_code))?;

        if !tpm_is_policy_cc(cc) {
            return Err(TpmKeyError::InvalidCc(val.command_code));
        }

        Ok(Self {
            cc,
            body: val.command_policy.as_ref().to_vec(),
        })
    }
}

/// Returns `true` when `cc` is a policy command allowed in a TPMKEY policy.
pub(crate) fn tpm_is_policy_cc(cc: TpmCc) -> bool {
    matches!(
        cc,
        TpmCc::PolicyNv
            | TpmCc::PolicySecret
            | TpmCc::PolicySigned
            | TpmCc::PolicyAuthorize
            | TpmCc::PolicyAuthValue
            | TpmCc::PolicyCommandCode
            | TpmCc::PolicyCounterTimer
            | TpmCc::PolicyCpHash
            | TpmCc::PolicyLocality
            | TpmCc::PolicyNameHash
            | TpmCc::PolicyOr
            | TpmCc::PolicyTicket
            | TpmCc::PolicyPcr
            | TpmCc::PolicyRestart
            | TpmCc::PolicyPhysicalPresence
            | TpmCc::PolicyDuplicationSelect
            | TpmCc::PolicyGetDigest
            | TpmCc::PolicyPassword
            | TpmCc::PolicyNvWritten
            | TpmCc::PolicyTemplate
            | TpmCc::PolicyAuthorizeNv
            | TpmCc::PolicyAcSendSelect
            | TpmCc::PolicyCapability
            | TpmCc::PolicyParameters
            | TpmCc::PolicyTransportSpdm
    )
}

impl From<&TpmKeyPolicyCommand> for TpmKeyCommandAsn1 {
    fn from(c: &TpmKeyPolicyCommand) -> Self {
        Self {
            command_code: c.cc as u32,
            command_policy: rasn::types::OctetString::from_slice(&c.body),
        }
    }
}
