// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2026 Jarkko Sakkinen

#![allow(clippy::all)]
#![allow(clippy::pedantic)]

#[path = "common/random.rs"]
mod random;

use crate::random::Rng;
use std::{fmt::Debug, ops::Range};
use tpm2_protocol::{
    TpmError, TpmField, TpmMarshal, TpmResult, TpmSized, TpmUnmarshal, TpmWireBytes, TpmWriter,
    basic::{Tpm2b, TpmBuffer, TpmHandle, TpmUint16, TpmUint32, TpmUint64, Tpml},
    constant::{MAX_SENSITIVE_DATA, MAX_SESSIONS, TPM_GENERATED_VALUE},
    data::{
        Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bMaxBuffer, Tpm2bName, Tpm2bNonce,
        Tpm2bSensitiveCreate, Tpm2bSensitiveCreateWire, Tpm2bSensitiveData, TpmAlgId, TpmCc, TpmRc,
        TpmRcBase, TpmSt, TpmSu, TpmaSession, TpmiYesNo, TpmsAttest, TpmsAuthCommand,
        TpmsAuthResponse, TpmsClockInfo, TpmsSensitiveCreate, TpmsSessionAuditInfo,
        TpmsTimeAttestInfo, TpmsTimeInfo, TpmuAttest, TpmuAttestView,
    },
    frame::{
        TpmCommand, TpmCommandView, TpmFlushContextCommand, TpmFrame, TpmGetRandomCommand,
        TpmGetRandomResponse, TpmHashSequenceStartCommand, TpmHashSequenceStartResponse,
        TpmPcrResetCommand, TpmPcrResetResponse, TpmResponse, TpmResponseOutcome, TpmResponseView,
        TpmSelfTestCommand, TpmSequenceUpdateCommand, TpmShutdownCommand, TpmStartupCommand,
        TpmStartupResponse, TpmStirRandomCommand, TpmUnmarshalBody, tpm_marshal_command,
        tpm_marshal_response,
    },
};

const HEADER: usize = 10;
const NO_SESSIONS: u16 = 0x8001;
const SESSIONS: u16 = 0x8002;
const SENTINEL: u8 = 0xa5;
const MAX_DIGEST: usize = 64;

/// `TPM_ST` values defined by the TCG specification.
const TPM_ST: &[u16] = &[
    0x00c4, 0x8000, 0x8001, 0x8002, 0x8014, 0x8015, 0x8016, 0x8017, 0x8018, 0x8019, 0x801a, 0x801c,
    0x8021, 0x8022, 0x8023, 0x8024, 0x8025,
];

#[derive(Clone, Copy)]
struct Command {
    cc: TpmCc,
    handles: usize,
    response_handles: usize,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn put16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put2b(out: &mut Vec<u8>, data: &[u8]) {
    put16(out, data.len() as u16);
    out.extend_from_slice(data);
}

fn header(tag: u16, size: u32, code: u32) -> Vec<u8> {
    let mut out = Vec::new();
    put16(&mut out, tag);
    put32(&mut out, size);
    put32(&mut out, code);
    out
}

fn set_size(bytes: &mut [u8]) {
    let size = bytes.len() as u32;
    bytes[2..6].copy_from_slice(&size.to_be_bytes());
}

fn write_size(bytes: &mut [u8], size: usize) {
    bytes[2..6].copy_from_slice(&(size as u32).to_be_bytes());
}

fn expect_err<T>(result: TpmResult<T>, expected: TpmError, bytes: &[u8]) {
    match result {
        Ok(_) => panic!("expected {expected:?}, got Ok: {}", hex(bytes)),
        Err(err) => assert_eq!(err, expected, "{}", hex(bytes)),
    }
}

fn expect_end_within<T>(result: TpmResult<T>, within: Range<usize>, bytes: &[u8]) {
    match result {
        Ok(_) => panic!("expected UnexpectedEnd, got Ok: {}", hex(bytes)),
        Err(TpmError::UnexpectedEnd { offset, .. }) if within.contains(&offset) => {}
        Err(err) => panic!(
            "expected UnexpectedEnd in {within:?}, got {err:?}: {}",
            hex(bytes)
        ),
    }
}

fn same_kind(a: &TpmError, b: &TpmError) -> bool {
    std::mem::discriminant(a) == std::mem::discriminant(b)
}

fn marshal<T: TpmMarshal + TpmSized>(value: &T) -> Vec<u8> {
    let mut buf = vec![SENTINEL; value.len() + 8];
    let len = {
        let mut writer = TpmWriter::new(&mut buf);
        value.marshal(&mut writer).unwrap();
        writer.len()
    };
    assert_eq!(len, value.len(), "TpmSized::len disagrees with marshal");
    buf.truncate(len);
    buf
}

fn random_bytes(rng: &mut Rng, max: usize) -> Vec<u8> {
    let len = if rng.one_in(8) {
        max
    } else {
        rng.range(0, max)
    };
    rng.bytes(len)
}

fn random_error_rc(rng: &mut Rng) -> TpmRc {
    loop {
        let raw = rng.u32() & 0xfff;
        if raw == 0 {
            continue;
        }
        if let Ok(rc) = TpmRc::try_from(raw) {
            return rc;
        }
    }
}

fn discover() -> Vec<Command> {
    let mut table = Vec::new();
    for raw in (0x100..=0x1ff).chain(0x2000_0000..=0x2000_00ff) {
        let Ok(cc) = TpmCc::try_from(raw) else {
            continue;
        };
        assert_eq!(cc.value(), raw);

        let probe = header(NO_SESSIONS, HEADER as u32, raw);
        let handles = match TpmCommand::cast(&probe) {
            Ok(_) => 0,
            Err(TpmError::UnexpectedEnd {
                offset: HEADER,
                needed,
                available: 0,
            }) if needed % 4 == 0 => needed / 4,
            Err(err) => panic!("{cc}: command probe failed: {err:?}"),
        };

        let probe = header(NO_SESSIONS, HEADER as u32, 0);
        let response = TpmResponse::cast(&probe).unwrap();
        let response_handles = match response.validate(cc) {
            Ok(()) => 0,
            Err(TpmError::UnexpectedEnd {
                offset: HEADER,
                needed,
                available: 0,
            }) if needed % 4 == 0 => needed / 4,
            Err(err) => panic!("{cc}: response probe failed: {err:?}"),
        };

        table.push(Command {
            cc,
            handles,
            response_handles,
        });
    }
    assert!(table.len() > 100, "dispatch table too small");
    table
}

fn lookup(table: &[Command], cc: TpmCc) -> Command {
    *table
        .iter()
        .find(|c| c.cc == cc)
        .expect("command code missing")
}

fn invalid_cc(rng: &mut Rng, table: &[Command]) -> u32 {
    loop {
        let raw = match rng.below(3) {
            0 => rng.u32(),
            1 => 0x100 + rng.below(0x100) as u32,
            _ => 0x2000_0000 + rng.below(0x100) as u32,
        };
        if !table.iter().any(|c| c.cc.value() == raw) {
            return raw;
        }
    }
}

fn invalid_tag(rng: &mut Rng) -> u16 {
    loop {
        let tag = if rng.bool() {
            *rng.pick(TPM_ST)
        } else {
            rng.u16()
        };
        if tag != NO_SESSIONS && tag != SESSIONS {
            return tag;
        }
    }
}

fn gen_auth_command(rng: &mut Rng) -> (TpmsAuthCommand, Vec<u8>) {
    let handle = rng.u32();
    let nonce = random_bytes(rng, MAX_DIGEST);
    let attributes = rng.u8();
    let hmac = random_bytes(rng, MAX_DIGEST);

    let mut bytes = Vec::new();
    put32(&mut bytes, handle);
    put2b(&mut bytes, &nonce);
    bytes.push(attributes);
    put2b(&mut bytes, &hmac);

    let auth = TpmsAuthCommand {
        session_handle: TpmHandle::new(handle),
        nonce: Tpm2bNonce::try_from(nonce.as_slice()).unwrap(),
        session_attributes: TpmaSession::from_bits_truncate(attributes),
        hmac: Tpm2bAuth::try_from(hmac.as_slice()).unwrap(),
    };
    (auth, bytes)
}

fn gen_auth_response(rng: &mut Rng) -> (TpmsAuthResponse, Vec<u8>) {
    let nonce = random_bytes(rng, MAX_DIGEST);
    let attributes = rng.u8();
    let hmac = random_bytes(rng, MAX_DIGEST);

    let mut bytes = Vec::new();
    put2b(&mut bytes, &nonce);
    bytes.push(attributes);
    put2b(&mut bytes, &hmac);

    let auth = TpmsAuthResponse {
        nonce: Tpm2bNonce::try_from(nonce.as_slice()).unwrap(),
        session_attributes: TpmaSession::from_bits_truncate(attributes),
        hmac: Tpm2bAuth::try_from(hmac.as_slice()).unwrap(),
    };
    (auth, bytes)
}

struct CommandFrame {
    bytes: Vec<u8>,
    command: Command,
    sessions: bool,
    auth: Range<usize>,
    session_ranges: Vec<Range<usize>>,
    session_handles: Vec<u32>,
    params: Range<usize>,
}

impl CommandFrame {
    fn generate(rng: &mut Rng, table: &[Command], session_count: Option<usize>) -> Self {
        let command = *rng.pick(table);
        let sessions = session_count.is_some() || rng.bool();
        let tag = if sessions { SESSIONS } else { NO_SESSIONS };
        let mut bytes = header(tag, 0, command.cc.value());

        for _ in 0..command.handles {
            put32(&mut bytes, rng.u32());
        }

        let mut auth = bytes.len()..bytes.len();
        let mut session_ranges = Vec::new();
        let mut session_handles = Vec::new();
        if sessions {
            let count = session_count.unwrap_or_else(|| rng.range(1, MAX_SESSIONS));
            let size_at = bytes.len();
            put32(&mut bytes, 0);
            let start = bytes.len();
            for _ in 0..count {
                let (auth, encoded) = gen_auth_command(rng);
                session_handles.push(auth.session_handle.value());
                session_ranges.push(bytes.len()..bytes.len() + encoded.len());
                bytes.extend_from_slice(&encoded);
            }
            let auth_size = (bytes.len() - start) as u32;
            bytes[size_at..start].copy_from_slice(&auth_size.to_be_bytes());
            auth = start..bytes.len();
        }

        let start = bytes.len();
        let len = rng.range(0, 64);
        bytes.extend(rng.bytes(len));
        let params = start..bytes.len();
        set_size(&mut bytes);

        Self {
            bytes,
            command,
            sessions,
            auth,
            session_ranges,
            session_handles,
            params,
        }
    }

    fn handle_area(&self) -> Range<usize> {
        HEADER..HEADER + 4 * self.command.handles
    }

    /// Expected envelope error for a frame truncated to `len` bytes with a
    /// matching size field.
    fn truncation_error(&self, len: usize) -> Option<TpmError> {
        let handles = 4 * self.command.handles;
        let body = len - HEADER;
        if body < handles {
            return Some(TpmError::UnexpectedEnd {
                offset: HEADER,
                needed: handles,
                available: body,
            });
        }
        if !self.sessions {
            return None;
        }
        let rest = body - handles;
        if rest < 4 {
            return Some(TpmError::UnexpectedEnd {
                offset: HEADER + handles,
                needed: 4,
                available: rest,
            });
        }
        if rest - 4 < self.auth.len() {
            return Some(TpmError::UnexpectedEnd {
                offset: HEADER + handles + 4,
                needed: self.auth.len(),
                available: rest - 4,
            });
        }
        None
    }
}

/// Asserts that every view and accessor of a well-formed command frame
/// borrows the expected region of the original buffer.
fn check_command(frame: &CommandFrame) {
    let bytes = &frame.bytes;
    let base = bytes.as_ptr();
    let command = TpmCommand::cast(bytes).unwrap_or_else(|e| panic!("{e:?}: {}", hex(bytes)));
    command.validate().unwrap();

    assert_eq!(command.as_bytes().as_ptr(), base);
    assert_eq!(command.len(), bytes.len());
    assert_eq!(command.size() as usize, bytes.len());
    assert_eq!(command.cc().unwrap(), frame.command.cc);
    let tag = if frame.sessions {
        TpmSt::Sessions
    } else {
        TpmSt::NoSessions
    };
    assert_eq!(command.tag().unwrap(), tag);

    let handles = command.handles().unwrap();
    assert_eq!(handles, &bytes[frame.handle_area()]);
    assert_eq!(handles.as_ptr(), base.wrapping_add(HEADER));

    let auth = command.auth_area().unwrap();
    assert_eq!(auth, &bytes[frame.auth.clone()]);
    assert_eq!(auth.as_ptr(), base.wrapping_add(frame.auth.start));

    let params = command.parameters().unwrap();
    assert_eq!(params, &bytes[frame.params.clone()]);
    assert_eq!(params.as_ptr(), base.wrapping_add(frame.params.start));

    let mut cursor = auth;
    for (range, handle) in frame.session_ranges.iter().zip(&frame.session_handles) {
        let (view, tail) = <TpmsAuthCommand as TpmField>::cast_prefix_field(cursor).unwrap();
        assert_eq!(view.as_bytes(), &bytes[range.clone()]);
        assert_eq!(view.as_bytes().as_ptr(), base.wrapping_add(range.start));
        assert_eq!(view.session_handle().unwrap().value(), *handle);

        let (owned, owned_tail) = TpmsAuthCommand::unmarshal(cursor).unwrap();
        assert_eq!(owned_tail.len(), tail.len());
        assert_eq!(owned.session_handle.value(), *handle);
        assert_eq!(marshal(&owned), &bytes[range.clone()]);
        cursor = tail;
    }
    assert!(cursor.is_empty());

    let view = TpmCommandView::cast_frame(bytes).unwrap();
    assert_eq!(view.cc(), frame.command.cc);
    assert_eq!(view.command().as_bytes().as_ptr(), base);
}

fn command_valid(rng: &mut Rng, table: &[Command]) {
    let frame = CommandFrame::generate(rng, table, None);
    check_command(&frame);

    let mut joined = frame.bytes.clone();
    let tail_len = rng.range(1, 16);
    joined.extend(rng.bytes(tail_len));
    let (command, tail) = TpmCommand::cast_prefix(&joined).unwrap();
    assert_eq!(command.as_bytes(), frame.bytes.as_slice());
    assert_eq!(tail, &joined[frame.bytes.len()..]);
    expect_err(
        TpmCommand::cast(&joined),
        TpmError::TrailingData {
            offset: frame.bytes.len(),
            actual: tail_len,
        },
        &joined,
    );

    let mut copy = frame.bytes.clone();
    let handles = rng.bytes(4 * frame.command.handles);
    let params = rng.bytes(frame.params.len());
    {
        let command = TpmCommand::cast_mut(&mut copy).unwrap();
        command.handles_mut().unwrap().copy_from_slice(&handles);
        command.parameters_mut().unwrap().copy_from_slice(&params);
    }
    let command = TpmCommand::cast(&copy).unwrap();
    command.validate().unwrap();
    assert_eq!(command.handles().unwrap(), handles.as_slice());
    assert_eq!(command.parameters().unwrap(), params.as_slice());
    assert_eq!(
        command.auth_area().unwrap(),
        &frame.bytes[frame.auth.clone()]
    );
}

fn command_truncated(rng: &mut Rng, table: &[Command]) {
    let frame = CommandFrame::generate(rng, table, None);
    let len = rng.below(frame.bytes.len());
    let cut = &frame.bytes[..len];
    let expected = if len < HEADER {
        TpmError::UnexpectedEnd {
            offset: 0,
            needed: HEADER,
            available: len,
        }
    } else {
        TpmError::UnexpectedEnd {
            offset: len,
            needed: frame.bytes.len() - len,
            available: 0,
        }
    };
    expect_err(TpmCommand::cast(cut), expected, cut);
    expect_err(TpmCommand::cast_prefix(cut), expected, cut);
    expect_err(TpmCommandView::cast_frame(cut), expected, cut);
}

fn command_resized(rng: &mut Rng, table: &[Command]) {
    let frame = CommandFrame::generate(rng, table, None);
    let full = frame.bytes.len();

    let len = rng.range(HEADER, full);
    let mut cut = frame.bytes[..len].to_vec();
    set_size(&mut cut);
    match frame.truncation_error(len) {
        Some(expected) => {
            expect_err(TpmCommand::cast(&cut), expected, &cut);
            expect_err(TpmCommandView::cast_frame(&cut), expected, &cut);
        }
        None => {
            let command = TpmCommand::cast(&cut).unwrap();
            command.validate().unwrap();
            assert_eq!(command.parameters().unwrap(), &cut[frame.params.start..]);
        }
    }

    let size = rng.below(full);
    let mut resized = frame.bytes.clone();
    write_size(&mut resized, size);
    let expected = if size < HEADER {
        TpmError::UnexpectedEnd {
            offset: 2,
            needed: HEADER,
            available: size,
        }
    } else {
        TpmError::TrailingData {
            offset: size,
            actual: full - size,
        }
    };
    expect_err(TpmCommand::cast(&resized), expected, &resized);
}

fn command_bad_header(rng: &mut Rng, table: &[Command]) {
    let frame = CommandFrame::generate(rng, table, None);

    let tag = invalid_tag(rng);
    let mut bytes = frame.bytes.clone();
    bytes[0..2].copy_from_slice(&tag.to_be_bytes());
    let expected = TpmError::InvalidTag {
        offset: 0,
        value: u64::from(tag),
    };
    expect_err(TpmCommand::cast(&bytes), expected, &bytes);
    expect_err(TpmCommandView::cast_frame(&bytes), expected, &bytes);

    let cc = invalid_cc(rng, table);
    let mut bytes = frame.bytes.clone();
    bytes[6..10].copy_from_slice(&cc.to_be_bytes());
    let expected = TpmError::InvalidCc {
        offset: 6,
        value: u64::from(cc),
    };
    expect_err(TpmCommand::cast(&bytes), expected, &bytes);
    expect_err(TpmCommandView::cast_frame(&bytes), expected, &bytes);
}

fn command_sessions(rng: &mut Rng, table: &[Command]) {
    let frame = CommandFrame::generate(rng, table, Some(MAX_SESSIONS + 1));
    let command = TpmCommand::cast(&frame.bytes).unwrap();
    let expected = TpmError::TooManyItems {
        offset: frame.session_ranges[MAX_SESSIONS].start,
        limit: MAX_SESSIONS,
        actual: MAX_SESSIONS + 1,
    };
    expect_err(command.validate(), expected, &frame.bytes);
    expect_err(
        TpmCommandView::cast_frame(&frame.bytes),
        expected,
        &frame.bytes,
    );

    let count = rng.range(1, MAX_SESSIONS);
    let frame = CommandFrame::generate(rng, table, Some(count));
    let cut = rng.range(frame.auth.start + 1, frame.auth.end - 1);
    let mut bytes = frame.bytes[..frame.auth.start - 4].to_vec();
    put32(&mut bytes, (cut - frame.auth.start) as u32);
    bytes.extend_from_slice(&frame.bytes[frame.auth.start..cut]);
    bytes.extend_from_slice(&frame.bytes[frame.params.clone()]);
    set_size(&mut bytes);

    let command = TpmCommand::cast(&bytes).unwrap();
    if frame.session_ranges.iter().any(|r| r.end == cut) {
        command.validate().unwrap();
    } else {
        expect_end_within(command.validate(), frame.auth.start..cut + 1, &bytes);
        expect_end_within(
            TpmCommandView::cast_frame(&bytes),
            frame.auth.start..cut + 1,
            &bytes,
        );
    }
}

struct ResponseFrame {
    bytes: Vec<u8>,
    command: Command,
    sessions: bool,
    params: Range<usize>,
    session_ranges: Vec<Range<usize>>,
}

impl ResponseFrame {
    fn generate(rng: &mut Rng, table: &[Command], session_count: Option<usize>) -> Self {
        let command = *rng.pick(table);
        let sessions = session_count.is_some() || rng.bool();
        let tag = if sessions { SESSIONS } else { NO_SESSIONS };
        let mut bytes = header(tag, 0, 0);

        for _ in 0..command.response_handles {
            put32(&mut bytes, rng.u32());
        }

        let param_len = rng.range(0, 64);
        if sessions {
            put32(&mut bytes, param_len as u32);
        }
        let start = bytes.len();
        bytes.extend(rng.bytes(param_len));
        let params = start..bytes.len();

        let mut session_ranges = Vec::new();
        if sessions {
            let count = session_count.unwrap_or_else(|| rng.range(0, MAX_SESSIONS));
            for _ in 0..count {
                let (_, encoded) = gen_auth_response(rng);
                session_ranges.push(bytes.len()..bytes.len() + encoded.len());
                bytes.extend_from_slice(&encoded);
            }
        }
        set_size(&mut bytes);

        Self {
            bytes,
            command,
            sessions,
            params,
            session_ranges,
        }
    }
}

fn response_valid(rng: &mut Rng, table: &[Command]) {
    let frame = ResponseFrame::generate(rng, table, None);
    let bytes = &frame.bytes;
    let base = bytes.as_ptr();
    let cc = frame.command.cc;

    let response = TpmResponse::cast(bytes).unwrap_or_else(|e| panic!("{e:?}: {}", hex(bytes)));
    response.validate(cc).unwrap();
    assert_eq!(response.as_bytes().as_ptr(), base);
    assert_eq!(response.len(), bytes.len());
    assert_eq!(response.size() as usize, bytes.len());
    assert_eq!(response.rc().unwrap(), TpmRc::Fmt0(TpmRcBase::Success));
    assert_eq!(response.body(), &bytes[HEADER..]);
    assert_eq!(response.body().as_ptr(), base.wrapping_add(HEADER));

    for range in &frame.session_ranges {
        let (view, _) =
            <TpmsAuthResponse as TpmField>::cast_prefix_field(&bytes[range.start..]).unwrap();
        assert_eq!(view.as_bytes(), &bytes[range.clone()]);
        let (owned, _) = TpmsAuthResponse::unmarshal(&bytes[range.start..]).unwrap();
        assert_eq!(marshal(&owned), &bytes[range.clone()]);
    }

    match TpmResponseView::cast_frame(cc, bytes).unwrap() {
        TpmResponseOutcome::Dispatched(view) => {
            assert_eq!(view.cc(), cc);
            assert_eq!(view.response().as_bytes().as_ptr(), base);
        }
        TpmResponseOutcome::Rejected(rc) => panic!("unexpected rejection: {rc}"),
    }

    let mut joined = bytes.clone();
    let tail_len = rng.range(1, 16);
    joined.extend(rng.bytes(tail_len));
    let (response, tail) = TpmResponse::cast_prefix(&joined).unwrap();
    assert_eq!(response.as_bytes(), bytes.as_slice());
    assert_eq!(tail, &joined[bytes.len()..]);
    expect_err(
        TpmResponse::cast(&joined),
        TpmError::TrailingData {
            offset: bytes.len(),
            actual: tail_len,
        },
        &joined,
    );

    let frame = ResponseFrame::generate(rng, table, Some(MAX_SESSIONS + 1));
    let response = TpmResponse::cast(&frame.bytes).unwrap();
    expect_err(
        response.validate(frame.command.cc),
        TpmError::TooManyItems {
            offset: frame.session_ranges[MAX_SESSIONS].start,
            limit: MAX_SESSIONS,
            actual: MAX_SESSIONS + 1,
        },
        &frame.bytes,
    );
}

fn response_truncated(rng: &mut Rng, table: &[Command]) {
    let frame = ResponseFrame::generate(rng, table, None);
    let full = frame.bytes.len();
    let cc = frame.command.cc;

    let len = rng.below(full);
    let cut = &frame.bytes[..len];
    let expected = if len < HEADER {
        TpmError::UnexpectedEnd {
            offset: 0,
            needed: HEADER,
            available: len,
        }
    } else {
        TpmError::UnexpectedEnd {
            offset: len,
            needed: full - len,
            available: 0,
        }
    };
    expect_err(TpmResponse::cast(cut), expected, cut);
    expect_err(TpmResponseView::cast_frame(cc, cut), expected, cut);

    let len = rng.range(HEADER, full);
    let mut cut = frame.bytes[..len].to_vec();
    set_size(&mut cut);
    let response = TpmResponse::cast(&cut).unwrap();
    let handles = 4 * frame.command.response_handles;
    let body = len - HEADER;
    let result = response.validate(cc);
    if body < handles {
        expect_err(
            result,
            TpmError::UnexpectedEnd {
                offset: HEADER,
                needed: handles,
                available: body,
            },
            &cut,
        );
    } else if !frame.sessions {
        result.unwrap();
    } else if body - handles < 4 {
        expect_err(
            result,
            TpmError::UnexpectedEnd {
                offset: HEADER + handles,
                needed: 4,
                available: body - handles,
            },
            &cut,
        );
    } else if len < frame.params.end {
        expect_err(
            result,
            TpmError::UnexpectedEnd {
                offset: HEADER + handles + 4,
                needed: frame.params.len(),
                available: len - frame.params.start,
            },
            &cut,
        );
    } else if len == frame.params.end || frame.session_ranges.iter().any(|r| r.end == len) {
        result.unwrap();
    } else {
        expect_end_within(result, frame.params.end..len + 1, &cut);
    }
}

fn response_error(rng: &mut Rng, table: &[Command]) {
    let command = *rng.pick(table);
    let rc = random_error_rc(rng);
    let bytes = header(NO_SESSIONS, HEADER as u32, rc.value());

    let response = TpmResponse::cast(&bytes).unwrap();
    response.validate(command.cc).unwrap();
    assert_eq!(response.rc().unwrap(), rc);
    assert_eq!(response.rc().unwrap().value(), rc.value());
    match TpmResponseView::cast_frame(command.cc, &bytes).unwrap() {
        TpmResponseOutcome::Rejected(actual) => assert_eq!(actual, rc),
        TpmResponseOutcome::Dispatched(_) => panic!("error response dispatched"),
    }

    let extra = rng.range(1, 32);
    let mut longer = bytes.clone();
    longer.extend(rng.bytes(extra));
    set_size(&mut longer);
    expect_err(
        TpmResponse::cast(&longer).unwrap().validate(command.cc),
        TpmError::TrailingData {
            offset: HEADER,
            actual: extra,
        },
        &longer,
    );

    let tagged = header(SESSIONS, HEADER as u32, rc.value());
    expect_err(
        TpmResponse::cast(&tagged).unwrap().validate(command.cc),
        TpmError::InvalidTag {
            offset: 0,
            value: u64::from(SESSIONS),
        },
        &tagged,
    );

    let raw = loop {
        let raw = if rng.bool() {
            rng.u32()
        } else {
            rng.u32() & 0xfff
        };
        if TpmRc::try_from(raw).is_err() {
            break raw;
        }
    };
    let bytes = header(NO_SESSIONS, HEADER as u32, raw);
    let expected = TpmError::InvalidRc {
        offset: 6,
        value: u64::from(raw),
    };
    expect_err(TpmResponse::cast(&bytes), expected, &bytes);
    expect_err(
        TpmResponseView::cast_frame(command.cc, &bytes),
        expected,
        &bytes,
    );

    let tag = invalid_tag(rng);
    let bytes = header(tag, HEADER as u32, 0);
    expect_err(
        TpmResponse::cast(&bytes),
        TpmError::InvalidTag {
            offset: 0,
            value: u64::from(tag),
        },
        &bytes,
    );
}

fn check_overflow(result: TpmResult<()>, storage: &[u8], cap: usize, expected: &[u8]) {
    match result {
        Err(TpmError::BufferOverflow {
            offset,
            needed,
            available,
        }) => {
            assert!(offset <= cap, "offset {offset} beyond capacity {cap}");
            assert_eq!(available, cap - offset);
            assert!(offset + needed > cap);
            assert_eq!(&storage[..offset], &expected[..offset]);
        }
        Err(err) => panic!("expected BufferOverflow, got {err:?}"),
        Ok(()) => panic!("expected BufferOverflow, got Ok"),
    }
    assert!(storage[cap..].iter().all(|b| *b == SENTINEL));
}

fn typed_command<C>(rng: &mut Rng, table: &[Command], command: C, handles: &[u32], params: &[u8])
where
    C: TpmFrame + TpmUnmarshalBody + PartialEq + Debug,
{
    assert_eq!(lookup(table, C::CC).handles, C::HANDLES);
    assert_eq!(TpmFrame::handles(&command), C::HANDLES);
    assert_eq!(handles.len(), C::HANDLES);

    let count = rng.range(0, 3);
    let sessions: Vec<_> = (0..count).map(|_| gen_auth_command(rng)).collect();
    let auths: Vec<TpmsAuthCommand> = sessions.iter().map(|s| s.0).collect();
    let tag = if auths.is_empty() {
        TpmSt::NoSessions
    } else {
        TpmSt::Sessions
    };

    let mut expected = header(tag.value(), 0, C::CC.value());
    for handle in handles {
        put32(&mut expected, *handle);
    }
    if !sessions.is_empty() {
        let auth: Vec<u8> = sessions.iter().flat_map(|s| s.1.clone()).collect();
        put32(&mut expected, auth.len() as u32);
        expected.extend_from_slice(&auth);
    }
    let params_start = expected.len();
    expected.extend_from_slice(params);
    set_size(&mut expected);

    let window = expected.len() + rng.range(0, 4);
    let mut storage = vec![SENTINEL; window + 8];
    let written = {
        let mut writer = TpmWriter::new(&mut storage[..window]);
        tpm_marshal_command(&command, tag, &auths, &mut writer).unwrap();
        writer.len()
    };
    assert_eq!(&storage[..written], expected.as_slice(), "{command:?}");
    assert!(storage[written..].iter().all(|b| *b == SENTINEL));

    let frame = TpmCommand::cast(&expected).unwrap();
    frame.validate().unwrap();
    assert_eq!(frame.parameters().unwrap(), params);
    assert_eq!(frame.unmarshal::<C>().unwrap(), command);

    let wrong = if C::CC == TpmCc::Startup {
        frame.unmarshal::<TpmShutdownCommand>().map(|_| ())
    } else {
        frame.unmarshal::<TpmStartupCommand>().map(|_| ())
    };
    expect_err(
        wrong,
        TpmError::InvalidCc {
            offset: 6,
            value: u64::from(C::CC.value()),
        },
        &expected,
    );

    let extra = rng.range(1, 4);
    let mut longer = expected.clone();
    longer.extend(rng.bytes(extra));
    set_size(&mut longer);
    expect_err(
        TpmCommand::cast(&longer).unwrap().unmarshal::<C>(),
        TpmError::TrailingData {
            offset: params.len(),
            actual: extra,
        },
        &longer,
    );

    if !params.is_empty() {
        let len = rng.range(params_start, expected.len() - 1);
        let mut shorter = expected[..len].to_vec();
        set_size(&mut shorter);
        expect_end_within(
            TpmCommand::cast(&shorter).unwrap().unmarshal::<C>(),
            0..params.len() + 1,
            &shorter,
        );
    }

    let cap = rng.below(expected.len());
    let mut storage = vec![SENTINEL; expected.len()];
    let result = {
        let mut writer = TpmWriter::new(&mut storage[..cap]);
        tpm_marshal_command(&command, tag, &auths, &mut writer)
    };
    check_overflow(result, &storage, cap, &expected);

    let mut storage = vec![0; expected.len() + 1024];
    let mismatched = if auths.is_empty() {
        TpmSt::Sessions
    } else {
        TpmSt::NoSessions
    };
    let unsupported = *rng.pick(&[TpmSt::Null, TpmSt::RspCommand, TpmSt::Creation]);
    for bad in [mismatched, unsupported] {
        let mut writer = TpmWriter::new(&mut storage);
        expect_err(
            tpm_marshal_command(&command, bad, &auths, &mut writer),
            TpmError::InvalidTag {
                offset: 0,
                value: u64::from(bad.value()),
            },
            &expected,
        );
        assert!(writer.is_empty());
    }

    let many: Vec<_> = (0..=MAX_SESSIONS)
        .map(|_| gen_auth_command(rng).0)
        .collect();
    let mut storage = vec![0; 4096];
    let mut writer = TpmWriter::new(&mut storage);
    expect_err(
        tpm_marshal_command(&command, TpmSt::Sessions, &many, &mut writer),
        TpmError::TooManyItems {
            offset: 0,
            limit: MAX_SESSIONS,
            actual: MAX_SESSIONS + 1,
        },
        &expected,
    );
}

fn typed_response<R>(rng: &mut Rng, table: &[Command], response: R, handles: &[u32], params: &[u8])
where
    R: TpmFrame + TpmUnmarshalBody + PartialEq + Debug,
{
    assert_eq!(lookup(table, R::CC).response_handles, R::HANDLES);
    assert_eq!(handles.len(), R::HANDLES);

    let count = rng.range(0, 3);
    let sessions: Vec<_> = (0..count).map(|_| gen_auth_response(rng)).collect();
    let auths: Vec<TpmsAuthResponse> = sessions.iter().map(|s| s.0).collect();
    let tag = if auths.is_empty() {
        NO_SESSIONS
    } else {
        SESSIONS
    };

    let mut expected = header(tag, 0, 0);
    for handle in handles {
        put32(&mut expected, *handle);
    }
    if !sessions.is_empty() {
        put32(&mut expected, params.len() as u32);
    }
    expected.extend_from_slice(params);
    for session in &sessions {
        expected.extend_from_slice(&session.1);
    }
    set_size(&mut expected);

    let success = TpmRc::Fmt0(TpmRcBase::Success);
    let window = expected.len() + rng.range(0, 4);
    let mut storage = vec![SENTINEL; window + 8];
    let written = {
        let mut writer = TpmWriter::new(&mut storage[..window]);
        tpm_marshal_response(&response, success, &auths, &mut writer).unwrap();
        writer.len()
    };
    assert_eq!(&storage[..written], expected.as_slice(), "{response:?}");
    assert!(storage[written..].iter().all(|b| *b == SENTINEL));

    let frame = TpmResponse::cast(&expected).unwrap();
    frame.validate(R::CC).unwrap();
    assert_eq!(frame.unmarshal::<R>().unwrap(), response);
    match TpmResponseView::cast_frame(R::CC, &expected).unwrap() {
        TpmResponseOutcome::Dispatched(view) => assert_eq!(view.cc(), R::CC),
        TpmResponseOutcome::Rejected(rc) => panic!("unexpected rejection: {rc}"),
    }

    let cap = rng.below(expected.len());
    let mut storage = vec![SENTINEL; expected.len()];
    let result = {
        let mut writer = TpmWriter::new(&mut storage[..cap]);
        tpm_marshal_response(&response, success, &auths, &mut writer)
    };
    check_overflow(result, &storage, cap, &expected);

    let rc = random_error_rc(rng);
    let mut storage = vec![0; 64];
    let written = {
        let mut writer = TpmWriter::new(&mut storage);
        tpm_marshal_response(&response, rc, &[], &mut writer).unwrap();
        writer.len()
    };
    assert_eq!(
        &storage[..written],
        header(NO_SESSIONS, HEADER as u32, rc.value()).as_slice()
    );

    let (auth, _) = gen_auth_response(rng);
    let mut writer = TpmWriter::new(&mut storage);
    expect_err(
        tpm_marshal_response(&response, rc, &[auth], &mut writer),
        TpmError::InvalidTag {
            offset: 0,
            value: u64::from(SESSIONS),
        },
        &expected,
    );

    let many: Vec<_> = (0..=MAX_SESSIONS)
        .map(|_| gen_auth_response(rng).0)
        .collect();
    let mut storage = vec![0; 4096];
    let mut writer = TpmWriter::new(&mut storage);
    expect_err(
        tpm_marshal_response(&response, success, &many, &mut writer),
        TpmError::TooManyItems {
            offset: 0,
            limit: MAX_SESSIONS,
            actual: MAX_SESSIONS + 1,
        },
        &expected,
    );
}

fn typed_commands(rng: &mut Rng, table: &[Command]) {
    match rng.below(9) {
        0 | 1 => {
            let su = *rng.pick(&[TpmSu::Clear, TpmSu::State]);
            let mut params = Vec::new();
            put16(&mut params, su.value());
            if rng.bool() {
                let command = TpmStartupCommand {
                    handles: [],
                    startup_type: su,
                };
                typed_command(rng, table, command, &[], &params);
            } else {
                let command = TpmShutdownCommand {
                    handles: [],
                    shutdown_type: su,
                };
                typed_command(rng, table, command, &[], &params);
            }
        }
        2 => {
            let count = rng.u16();
            let command = TpmGetRandomCommand {
                handles: [],
                bytes_requested: TpmUint16::new(count),
            };
            typed_command(rng, table, command, &[], &count.to_be_bytes());
        }
        3 => {
            let handle = rng.u32();
            let command = TpmFlushContextCommand {
                handles: [],
                flush_handle: TpmHandle::new(handle),
            };
            typed_command(rng, table, command, &[], &handle.to_be_bytes());
        }
        4 => {
            let handle = rng.u32();
            let command = TpmPcrResetCommand {
                handles: [TpmHandle::new(handle)],
            };
            typed_command(rng, table, command, &[handle], &[]);
        }
        5 => {
            let data = random_bytes(rng, MAX_SENSITIVE_DATA);
            let mut params = Vec::new();
            put2b(&mut params, &data);
            let command = TpmStirRandomCommand {
                handles: [],
                in_data: Tpm2bSensitiveData::try_from(data.as_slice()).unwrap(),
            };
            typed_command(rng, table, command, &[], &params);
        }
        6 => {
            let handle = rng.u32();
            let data = random_bytes(rng, 1024);
            let mut params = Vec::new();
            put2b(&mut params, &data);
            let command = TpmSequenceUpdateCommand {
                handles: [TpmHandle::new(handle)],
                buffer: Tpm2bMaxBuffer::try_from(data.as_slice()).unwrap(),
            };
            typed_command(rng, table, command, &[handle], &params);
        }
        7 => {
            let full = rng.bool();
            let command = TpmSelfTestCommand {
                handles: [],
                full_test: TpmiYesNo(full),
            };
            typed_command(rng, table, command, &[], &[u8::from(full)]);
        }
        _ => {
            let auth = random_bytes(rng, MAX_DIGEST);
            let alg = *rng.pick(&[
                TpmAlgId::Sha1,
                TpmAlgId::Sha256,
                TpmAlgId::Sha384,
                TpmAlgId::Sha512,
                TpmAlgId::Null,
            ]);
            let mut params = Vec::new();
            put2b(&mut params, &auth);
            put16(&mut params, alg.value());
            let command = TpmHashSequenceStartCommand {
                handles: [],
                auth: Tpm2bAuth::try_from(auth.as_slice()).unwrap(),
                hash_alg: alg,
            };
            typed_command(rng, table, command, &[], &params);
        }
    }
}

fn typed_responses(rng: &mut Rng, table: &[Command]) {
    match rng.below(4) {
        0 => typed_response(rng, table, TpmStartupResponse { handles: [] }, &[], &[]),
        1 => typed_response(rng, table, TpmPcrResetResponse { handles: [] }, &[], &[]),
        2 => {
            let data = random_bytes(rng, MAX_DIGEST);
            let mut params = Vec::new();
            put2b(&mut params, &data);
            let response = TpmGetRandomResponse {
                handles: [],
                random_bytes: Tpm2bDigest::try_from(data.as_slice()).unwrap(),
            };
            typed_response(rng, table, response, &[], &params);
        }
        _ => {
            let handle = rng.u32();
            let response = TpmHashSequenceStartResponse {
                handles: [TpmHandle::new(handle)],
            };
            typed_response(rng, table, response, &[handle], &[]);
        }
    }
}

fn tpm2b(rng: &mut Rng) {
    const CAPACITY: usize = 64;
    let size = rng.range(0, CAPACITY + 16);
    let data = rng.bytes(size);
    let mut bytes = Vec::new();
    put2b(&mut bytes, &data);

    if size > CAPACITY {
        let expected = TpmError::TooManyBytes {
            offset: 0,
            limit: CAPACITY,
            actual: size,
        };
        expect_err(Tpm2b::<CAPACITY>::cast(&bytes), expected, &bytes);
        expect_err(Tpm2b::<CAPACITY>::cast_prefix(&bytes), expected, &bytes);
        expect_err(TpmBuffer::<CAPACITY>::unmarshal(&bytes), expected, &bytes);
        expect_err(
            TpmBuffer::<CAPACITY>::try_from(data.as_slice()),
            TpmError::BufferOverflow {
                offset: 0,
                needed: size,
                available: CAPACITY,
            },
            &bytes,
        );
        return;
    }

    let view = Tpm2b::<CAPACITY>::cast(&bytes).unwrap();
    assert_eq!(view.size(), size);
    assert_eq!(view.data(), data.as_slice());
    assert_eq!(view.data().as_ptr(), bytes.as_ptr().wrapping_add(2));
    assert_eq!(view.len(), size + 2);
    assert_eq!(view.is_empty(), size == 0);

    let buffer = TpmBuffer::<CAPACITY>::try_from(data.as_slice()).unwrap();
    assert_eq!(&*buffer, data.as_slice());
    assert_eq!(marshal(&buffer), bytes);

    let tail_len = rng.range(1, 8);
    let mut joined = bytes.clone();
    joined.extend(rng.bytes(tail_len));
    let (view, tail) = Tpm2b::<CAPACITY>::cast_prefix(&joined).unwrap();
    assert_eq!(view.data(), data.as_slice());
    assert_eq!(tail, &joined[bytes.len()..]);
    let (owned, tail) = TpmBuffer::<CAPACITY>::unmarshal(&joined).unwrap();
    assert_eq!(owned, buffer);
    assert_eq!(tail, &joined[bytes.len()..]);
    expect_err(
        Tpm2b::<CAPACITY>::cast(&joined),
        TpmError::TrailingData {
            offset: bytes.len(),
            actual: tail_len,
        },
        &joined,
    );

    let len = rng.below(bytes.len());
    let cut = &bytes[..len];
    let expected = if len < 2 {
        TpmError::UnexpectedEnd {
            offset: 0,
            needed: 2,
            available: len,
        }
    } else {
        TpmError::UnexpectedEnd {
            offset: 2,
            needed: size,
            available: len - 2,
        }
    };
    expect_err(Tpm2b::<CAPACITY>::cast(cut), expected, cut);
    expect_err(Tpm2b::<CAPACITY>::cast_prefix(cut), expected, cut);
    expect_err(TpmBuffer::<CAPACITY>::unmarshal(cut), expected, cut);
}

fn tpml(rng: &mut Rng) {
    const CAPACITY: usize = 8;
    let count = if rng.one_in(8) {
        rng.u32() as usize
    } else {
        rng.range(0, CAPACITY + 2)
    };
    let mut bytes = Vec::new();
    put32(&mut bytes, count as u32);

    if count > CAPACITY {
        let expected = TpmError::TooManyItems {
            offset: 0,
            limit: CAPACITY,
            actual: count,
        };
        expect_err(Tpml::<CAPACITY>::cast(&bytes), expected, &bytes);
        expect_err(
            Tpml::<CAPACITY>::cast_items::<TpmUint16>(&bytes),
            expected,
            &bytes,
        );
        return;
    }

    let items: Vec<u16> = (0..count).map(|_| rng.u16()).collect();
    for item in &items {
        put16(&mut bytes, *item);
    }

    let list = Tpml::<CAPACITY>::cast_items::<TpmUint16>(&bytes).unwrap();
    assert_eq!(list.count(), count);
    assert_eq!(list.is_empty(), count == 0);
    assert_eq!(list.len(), bytes.len());
    assert_eq!(list.items_bytes(), &bytes[4..]);
    let values: Vec<u16> = list
        .items::<TpmUint16>()
        .map(|i| i.unwrap().value())
        .collect();
    assert_eq!(values, items);

    let tail_len = rng.range(1, 8);
    let mut joined = bytes.clone();
    joined.extend(rng.bytes(tail_len));
    let (list, tail) = Tpml::<CAPACITY>::cast_prefix_items::<TpmUint16>(&joined).unwrap();
    assert_eq!(list.as_bytes(), bytes.as_slice());
    assert_eq!(tail, &joined[bytes.len()..]);
    expect_err(
        Tpml::<CAPACITY>::cast_items::<TpmUint16>(&joined),
        TpmError::TrailingData {
            offset: bytes.len(),
            actual: tail_len,
        },
        &joined,
    );

    let len = rng.below(bytes.len());
    let cut = &bytes[..len];
    if len < 4 {
        let expected = TpmError::UnexpectedEnd {
            offset: 0,
            needed: 4,
            available: len,
        };
        expect_err(Tpml::<CAPACITY>::cast(cut), expected, cut);
        expect_err(
            Tpml::<CAPACITY>::cast_items::<TpmUint16>(cut),
            expected,
            cut,
        );
        return;
    }

    let list = Tpml::<CAPACITY>::cast(cut).unwrap();
    expect_end_within(
        Tpml::<CAPACITY>::cast_items::<TpmUint16>(cut),
        0..len + 1,
        cut,
    );
    let complete = (len - 4) / 2;
    let mut iter = list.items::<TpmUint16>();
    for item in &items[..complete] {
        assert_eq!(iter.next().unwrap().unwrap().value(), *item);
    }
    assert!(matches!(
        iter.next(),
        Some(Err(TpmError::UnexpectedEnd { .. }))
    ));
    assert!(iter.next().is_none());
}

fn integers(rng: &mut Rng) {
    let len = rng.range(0, 12);
    let bytes = rng.bytes(len);

    fn check<const N: usize>(
        bytes: &[u8],
        value: impl Fn(&[u8]) -> u64,
        read: impl Fn(&[u8]) -> TpmResult<(u64, usize)>,
    ) {
        let result = read(bytes);
        if bytes.len() < N {
            expect_err(
                result,
                TpmError::UnexpectedEnd {
                    offset: 0,
                    needed: N,
                    available: bytes.len(),
                },
                bytes,
            );
        } else {
            let (actual, tail) = result.unwrap();
            assert_eq!(actual, value(&bytes[..N]));
            assert_eq!(tail, bytes.len() - N);
        }
    }

    check::<2>(
        &bytes,
        |b| u64::from(u16::from_be_bytes([b[0], b[1]])),
        |b| TpmUint16::cast_prefix(b).map(|(v, t)| (u64::from(v.value()), t.len())),
    );
    check::<4>(
        &bytes,
        |b| u64::from(u32::from_be_bytes(b.try_into().unwrap())),
        |b| TpmUint32::cast_prefix(b).map(|(v, t)| (u64::from(v.value()), t.len())),
    );
    check::<8>(
        &bytes,
        |b| u64::from_be_bytes(b.try_into().unwrap()),
        |b| TpmUint64::cast_prefix(b).map(|(v, t)| (v.value(), t.len())),
    );

    match bytes.len() {
        4 => assert_eq!(
            TpmWireBytes::<4>::cast(&bytes).unwrap().as_bytes(),
            &bytes[..]
        ),
        n if n < 4 => expect_err(
            TpmWireBytes::<4>::cast(&bytes),
            TpmError::UnexpectedEnd {
                offset: 0,
                needed: 4,
                available: n,
            },
            &bytes,
        ),
        n => {
            expect_err(
                TpmWireBytes::<4>::cast(&bytes),
                TpmError::TrailingData {
                    offset: 4,
                    actual: n - 4,
                },
                &bytes,
            );
            let (wire, tail) = TpmWireBytes::<4>::cast_prefix(&bytes).unwrap();
            assert_eq!(wire.as_bytes(), &bytes[..4]);
            assert_eq!(tail, &bytes[4..]);
        }
    }

    let value = rng.u32();
    let encoded = marshal(&TpmUint32::new(value));
    assert_eq!(encoded, value.to_be_bytes());
    let (decoded, rest) = TpmUint32::unmarshal(&encoded).unwrap();
    assert_eq!(decoded.value(), value);
    assert!(rest.is_empty());
}

fn enums(rng: &mut Rng) {
    let raw = if rng.bool() {
        *rng.pick(TPM_ST)
    } else {
        rng.u16()
    };
    match TpmSt::try_from(raw) {
        Ok(tag) => {
            assert!(TPM_ST.contains(&raw), "{raw:#06x} accepted");
            assert_eq!(tag.value(), raw);
            assert!(tag.to_string().starts_with("TPM_ST_"));
            let encoded = marshal(&tag);
            assert_eq!(encoded, raw.to_be_bytes());
            assert_eq!(TpmSt::unmarshal(&encoded).unwrap().0, tag);
        }
        Err(err) => {
            assert!(!TPM_ST.contains(&raw), "{raw:#06x} rejected");
            assert_eq!(
                err,
                TpmError::VariantNotAvailable {
                    offset: 0,
                    value: u64::from(raw),
                }
            );
            expect_err(
                TpmSt::unmarshal(&raw.to_be_bytes()),
                err,
                &raw.to_be_bytes(),
            );
        }
    }

    let byte = [rng.u8()];
    let result = TpmiYesNo::unmarshal(&byte);
    match byte[0] {
        0 | 1 => assert_eq!(result.unwrap().0, TpmiYesNo(byte[0] == 1)),
        raw => expect_err(
            result,
            TpmError::InvalidBoolean {
                offset: 0,
                value: u64::from(raw),
            },
            &byte,
        ),
    }
}

fn errors(rng: &mut Rng) {
    let offset = if rng.one_in(8) {
        usize::MAX - rng.below(4)
    } else {
        rng.below(1 << 16)
    };
    let delta = if rng.one_in(8) {
        usize::MAX
    } else {
        rng.below(1 << 16)
    };
    let a = rng.below(1 << 16);
    let b = rng.below(1 << 16);
    let value = rng.u64();

    let make = |offset: usize| -> [(TpmError, &'static str); 12] {
        [
            (
                TpmError::BufferOverflow {
                    offset,
                    needed: a,
                    available: b,
                },
                "buffer overflow",
            ),
            (
                TpmError::IntegerTooLarge { offset, value },
                "integer too large",
            ),
            (
                TpmError::InvalidBoolean { offset, value },
                "invalid boolean",
            ),
            (TpmError::InvalidCc { offset, value }, "invalid cc"),
            (
                TpmError::InvalidMagicNumber { offset, value },
                "invalid magic number",
            ),
            (TpmError::InvalidRc { offset, value }, "invalid rc"),
            (TpmError::InvalidTag { offset, value }, "invalid tag"),
            (
                TpmError::TooManyBytes {
                    offset,
                    limit: a,
                    actual: b,
                },
                "too many bytes",
            ),
            (
                TpmError::TooManyItems {
                    offset,
                    limit: a,
                    actual: b,
                },
                "too many items",
            ),
            (
                TpmError::TrailingData { offset, actual: a },
                "trailing data",
            ),
            (
                TpmError::UnexpectedEnd {
                    offset,
                    needed: a,
                    available: b,
                },
                "unexpected end",
            ),
            (
                TpmError::VariantNotAvailable { offset, value },
                "variant not available",
            ),
        ]
    };

    let index = rng.below(12);
    let (err, name) = make(offset)[index];
    let (rebased, _) = make(offset.saturating_add(delta))[index];
    assert_eq!(err.offset(), offset);
    assert_eq!(err.to_string(), name);
    assert_eq!(err.rebase(delta), rebased);
    assert_eq!(err.rebase(0), err);
}

fn gen_clock(rng: &mut Rng, out: &mut Vec<u8>) -> TpmsClockInfo {
    let clock = rng.u64();
    let reset = rng.u32();
    let restart = rng.u32();
    let safe = rng.bool();
    put64(out, clock);
    put32(out, reset);
    put32(out, restart);
    out.push(u8::from(safe));
    TpmsClockInfo {
        clock: TpmUint64::new(clock),
        reset_count: TpmUint32::new(reset),
        restart_count: TpmUint32::new(restart),
        safe: TpmiYesNo(safe),
    }
}

fn attest(rng: &mut Rng) {
    let signer = random_bytes(rng, MAX_DIGEST + 2);
    let extra = random_bytes(rng, MAX_DIGEST + 2);
    let firmware = rng.u64();
    let session_audit = rng.bool();
    let attest_type = if session_audit {
        TpmSt::AttestSessionAudit
    } else {
        TpmSt::AttestTime
    };

    let mut expected = Vec::new();
    put32(&mut expected, TPM_GENERATED_VALUE);
    put16(&mut expected, attest_type.value());
    put2b(&mut expected, &signer);
    put2b(&mut expected, &extra);
    let clock_start = expected.len();
    let clock_info = gen_clock(rng, &mut expected);
    let clock_end = expected.len();
    put64(&mut expected, firmware);
    let attested_start = expected.len();
    let attested = if session_audit {
        let exclusive = rng.bool();
        let digest = random_bytes(rng, MAX_DIGEST);
        expected.push(u8::from(exclusive));
        put2b(&mut expected, &digest);
        TpmuAttest::SessionAudit(TpmsSessionAuditInfo {
            exclusive_session: TpmiYesNo(exclusive),
            session_digest: Tpm2bDigest::try_from(digest.as_slice()).unwrap(),
        })
    } else {
        let time = rng.u64();
        put64(&mut expected, time);
        let clock_info = gen_clock(rng, &mut expected);
        let firmware = rng.u64();
        put64(&mut expected, firmware);
        TpmuAttest::Time(TpmsTimeAttestInfo {
            time: TpmsTimeInfo {
                time: TpmUint64::new(time),
                clock_info,
            },
            firmware_version: TpmUint64::new(firmware),
        })
    };

    let value = TpmsAttest {
        attest_type,
        qualified_signer: Tpm2bName::try_from(signer.as_slice()).unwrap(),
        extra_data: Tpm2bData::try_from(extra.as_slice()).unwrap(),
        clock_info,
        firmware_version: TpmUint64::new(firmware),
        attested,
    };
    assert_eq!(marshal(&value), expected);

    let tail_len = rng.range(0, 8);
    let mut joined = expected.clone();
    joined.extend(rng.bytes(tail_len));

    let (view, rest) = <TpmsAttest as TpmField>::cast_prefix_field(&joined).unwrap();
    assert_eq!(view.attest_type, attest_type);
    assert_eq!(view.qualified_signer.data(), signer.as_slice());
    assert_eq!(view.extra_data.data(), extra.as_slice());
    assert_eq!(
        view.clock_info.as_bytes(),
        &expected[clock_start..clock_end]
    );
    assert_eq!(view.firmware_version, firmware);
    match (&view.attested, session_audit) {
        (TpmuAttestView::SessionAudit(info), true) => {
            assert_eq!(info.as_bytes(), &expected[attested_start..]);
            assert_eq!(
                info.as_bytes().as_ptr(),
                joined.as_ptr().wrapping_add(attested_start)
            );
        }
        (TpmuAttestView::Time(info), false) => {
            assert_eq!(info.as_bytes(), &expected[attested_start..]);
        }
        _ => panic!("unexpected attestation body"),
    }
    assert_eq!(rest, &joined[expected.len()..]);

    let (owned, rest) = TpmsAttest::unmarshal(&joined).unwrap();
    assert_eq!(owned, value);
    assert_eq!(rest, &joined[expected.len()..]);

    let magic = loop {
        let magic = rng.u32();
        if magic != TPM_GENERATED_VALUE {
            break magic;
        }
    };
    let mut corrupt = expected.clone();
    corrupt[..4].copy_from_slice(&magic.to_be_bytes());
    let expected_err = TpmError::InvalidMagicNumber {
        offset: 0,
        value: u64::from(magic),
    };
    expect_err(
        <TpmsAttest as TpmField>::cast_prefix_field(&corrupt),
        expected_err,
        &corrupt,
    );
    expect_err(TpmsAttest::unmarshal(&corrupt), expected_err, &corrupt);

    let len = rng.below(expected.len());
    let cut = &expected[..len];
    let view_err = <TpmsAttest as TpmField>::cast_prefix_field(cut)
        .err()
        .expect("truncated attestation accepted");
    let owned_err = TpmsAttest::unmarshal(cut)
        .err()
        .expect("truncated attestation accepted");
    assert!(
        matches!(view_err, TpmError::UnexpectedEnd { .. }),
        "{view_err:?}"
    );
    assert!(
        same_kind(&view_err, &owned_err),
        "{view_err:?} != {owned_err:?}"
    );

    let mut corrupt = expected.clone();
    corrupt[clock_end - 1] = rng.range(2, 255) as u8;
    let view_err = <TpmsAttest as TpmField>::cast_prefix_field(&corrupt)
        .err()
        .expect("invalid boolean accepted");
    let owned_err = TpmsAttest::unmarshal(&corrupt)
        .err()
        .expect("invalid boolean accepted");
    assert!(
        matches!(view_err, TpmError::InvalidBoolean { .. }),
        "{view_err:?}"
    );
    assert!(
        same_kind(&view_err, &owned_err),
        "{view_err:?} != {owned_err:?}"
    );
}

fn nested(rng: &mut Rng) {
    let user_auth = random_bytes(rng, MAX_DIGEST);
    let data = random_bytes(rng, MAX_SENSITIVE_DATA);

    let mut inner = Vec::new();
    put2b(&mut inner, &user_auth);
    put2b(&mut inner, &data);
    let mut expected = Vec::new();
    put2b(&mut expected, &inner);

    let value = Tpm2bSensitiveCreate {
        inner: TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::try_from(user_auth.as_slice()).unwrap(),
            data: Tpm2bSensitiveData::try_from(data.as_slice()).unwrap(),
        },
    };
    assert_eq!(marshal(&value), expected);
    let (owned, rest) = Tpm2bSensitiveCreate::unmarshal(&expected).unwrap();
    assert_eq!(owned, value);
    assert!(rest.is_empty());

    let base = expected.as_ptr();
    let wrapper = Tpm2bSensitiveCreateWire::cast(&expected).unwrap();
    let inner_view = wrapper.inner().unwrap();
    let (auth_view, rest) =
        <Tpm2bAuth as TpmField>::cast_prefix_field(inner_view.as_bytes()).unwrap();
    let (data_view, rest) = <Tpm2bSensitiveData as TpmField>::cast_prefix_field(rest).unwrap();
    assert!(rest.is_empty());
    assert_eq!(wrapper.as_bytes().as_ptr(), base);
    assert_eq!(inner_view.as_bytes().as_ptr(), base.wrapping_add(2));
    assert_eq!(auth_view.data(), user_auth.as_slice());
    assert_eq!(auth_view.data().as_ptr(), base.wrapping_add(4));
    assert_eq!(data_view.data(), data.as_slice());
    assert_eq!(
        data_view.data().as_ptr(),
        base.wrapping_add(6 + user_auth.len())
    );

    let both = |bytes: &[u8], expected: TpmError| {
        expect_err(Tpm2bSensitiveCreateWire::cast(bytes), expected, bytes);
        expect_err(Tpm2bSensitiveCreate::unmarshal(bytes), expected, bytes);
    };

    let limit = TpmsSensitiveCreate::SIZE;
    if inner.len() < limit {
        let extra = rng.range(1, (limit - inner.len()).min(8));
        let mut longer = expected.clone();
        longer.extend(rng.bytes(extra));
        longer[..2].copy_from_slice(&((inner.len() + extra) as u16).to_be_bytes());
        both(
            &longer,
            TpmError::TrailingData {
                offset: 2 + inner.len(),
                actual: extra,
            },
        );
    }

    let size = rng.range(limit + 1, 0xffff);
    let mut oversized = expected.clone();
    oversized[..2].copy_from_slice(&(size as u16).to_be_bytes());
    both(
        &oversized,
        TpmError::TooManyBytes {
            offset: 2,
            limit,
            actual: size,
        },
    );

    let len = rng.range(2, expected.len() - 1);
    both(
        &expected[..len],
        TpmError::UnexpectedEnd {
            offset: 2,
            needed: inner.len(),
            available: len - 2,
        },
    );

    let len = rng.range(0, inner.len() - 1);
    let mut shrunk = expected[..2 + len].to_vec();
    shrunk[..2].copy_from_slice(&(len as u16).to_be_bytes());
    let view_err = Tpm2bSensitiveCreateWire::cast(&shrunk)
        .err()
        .expect("shrunk wrapper accepted");
    let owned_err = Tpm2bSensitiveCreate::unmarshal(&shrunk)
        .err()
        .expect("shrunk wrapper accepted");
    assert!(
        matches!(view_err, TpmError::UnexpectedEnd { .. }),
        "{view_err:?}"
    );
    assert!(
        same_kind(&view_err, &owned_err),
        "{view_err:?} != {owned_err:?}"
    );
}

fn main() {
    let table = discover();
    random::run("message", |rng| match rng.below(17) {
        0 | 1 => command_valid(rng, &table),
        2 => command_truncated(rng, &table),
        3 => command_resized(rng, &table),
        4 => command_bad_header(rng, &table),
        5 => command_sessions(rng, &table),
        6 | 7 => response_valid(rng, &table),
        8 => response_truncated(rng, &table),
        9 => response_error(rng, &table),
        10 => typed_commands(rng, &table),
        11 => typed_responses(rng, &table),
        12 => tpm2b(rng),
        13 => tpml(rng),
        14 => integers(rng),
        15 => match rng.below(2) {
            0 => enums(rng),
            _ => errors(rng),
        },
        _ => match rng.below(2) {
            0 => attest(rng),
            _ => nested(rng),
        },
    });
}
