// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Jarkko Sakkinen

//! Property tests. The population seed is printed by every test and can be
//! pinned with `TPM2_TEST_SEED` to reproduce a failing run.

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use proptest::{prelude::*, test_runner::RngSeed};
use std::{
    cell::RefCell,
    collections::hash_map::RandomState,
    hash::{BuildHasher, Hasher},
    io::{Cursor, Read, Write},
    rc::Rc,
    sync::OnceLock,
};
use tpm2_device::{
    TpmDevice, TpmDeviceError, TpmResponder, TpmStreamTransport, TpmTransport, read_frame,
    with_device, write_frame,
};
use tpm2_protocol::{
    TpmWriter,
    basic::{TpmHandle, TpmUint64},
    constant::{MAX_HANDLES, TPM_MAX_COMMAND_SIZE},
    data::{
        Tpm2b, TpmCap, TpmCc, TpmHt, TpmRc, TpmRcBase, TpmRcFmt1, TpmRcIndex, TpmRh, TpmiYesNo,
        TpmlHandle, TpmsCapabilityData, TpmsContext, TpmuCapabilities,
    },
    frame::{
        TpmCommand, TpmContextLoadCommand, TpmContextLoadResponse, TpmFlushContextCommand,
        TpmFlushContextResponse, TpmFrame, TpmGetCapabilityCommand, TpmGetCapabilityResponse,
        TpmResponse, TpmResponseOutcome, TpmResponseView, tpm_marshal_response,
    },
};

const SEED_VAR: &str = "TPM2_TEST_SEED";
const CASES: u32 = 1024;
const HEADER: usize = 10;

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

/// An in-memory duplex stream that records written bytes.
struct Duplex {
    input: Cursor<Vec<u8>>,
    output: Rc<RefCell<Vec<u8>>>,
}

impl Read for Duplex {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.input.read(buf)
    }
}

impl Write for Duplex {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.output.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn frame(tag: u16, code: u32, body: &[u8]) -> Vec<u8> {
    let mut frame = tag.to_be_bytes().to_vec();
    frame.extend_from_slice(&u32::try_from(HEADER + body.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(&code.to_be_bytes());
    frame.extend_from_slice(body);
    frame
}

fn marshal_response<R: TpmFrame>(response: &R, rc: TpmRc) -> Vec<u8> {
    let mut buf = vec![0; TPM_MAX_COMMAND_SIZE];
    let len = {
        let mut writer = TpmWriter::new(&mut buf);
        tpm_marshal_response(response, rc, &[], &mut writer).unwrap();
        writer.len()
    };
    buf.truncate(len);
    buf
}

const SUCCESS: TpmRc = TpmRc::Fmt0(TpmRcBase::Success);

/// Shared state of the simulated TPM.
#[derive(Default)]
struct State {
    handles: Vec<u32>,
    page: usize,
    load: Option<TpmRc>,
    loaded: u32,
    reply: Option<Vec<u8>>,
    pending: Vec<u8>,
    capability_queries: Vec<(u32, u32)>,
    flushed: Vec<u32>,
}

/// A transport simulating the TPM side of an exchange.
struct Simulator(Rc<RefCell<State>>);

impl Simulator {
    fn respond(state: &mut State, frame: &[u8]) -> Vec<u8> {
        if let Some(reply) = state.reply.clone() {
            return reply;
        }

        let command = TpmCommand::cast(frame).unwrap();
        command.validate().unwrap();
        match command.cc().unwrap() {
            TpmCc::GetCapability => {
                let body = command.unmarshal::<TpmGetCapabilityCommand>().unwrap();
                assert_eq!(body.cap, TpmCap::Handles);
                let property = body.property.value();
                let count = body.property_count.value();
                state.capability_queries.push((property, count));

                let take = state.page.min(usize::try_from(count).unwrap());
                let matching: Vec<u32> = state
                    .handles
                    .iter()
                    .copied()
                    .filter(|h| *h >= property)
                    .collect();
                let mut list = TpmlHandle::new();
                for handle in matching.iter().take(take) {
                    list.try_push(TpmHandle::new(*handle)).unwrap();
                }
                let response = TpmGetCapabilityResponse {
                    handles: [],
                    more_data: TpmiYesNo(matching.len() > take),
                    capability_data: TpmsCapabilityData {
                        capability: TpmCap::Handles,
                        data: TpmuCapabilities::Handles(list),
                    },
                };
                marshal_response(&response, SUCCESS)
            }
            TpmCc::ContextLoad => {
                command.unmarshal::<TpmContextLoadCommand>().unwrap();
                match state.load {
                    Some(rc) => marshal_response(
                        &TpmContextLoadResponse {
                            handles: [0.into()],
                        },
                        rc,
                    ),
                    None => marshal_response(
                        &TpmContextLoadResponse {
                            handles: [TpmHandle::new(state.loaded)],
                        },
                        SUCCESS,
                    ),
                }
            }
            TpmCc::FlushContext => {
                let body = command.unmarshal::<TpmFlushContextCommand>().unwrap();
                state.flushed.push(body.flush_handle.value());
                marshal_response(&TpmFlushContextResponse { handles: [] }, SUCCESS)
            }
            cc => panic!("unexpected command {cc}"),
        }
    }
}

impl TpmTransport for Simulator {
    fn send(&mut self, frame: &[u8]) -> Result<(), TpmDeviceError> {
        let mut state = self.0.borrow_mut();
        let response = Self::respond(&mut state, frame);
        state.pending = response;
        Ok(())
    }

    fn recv(&mut self, buf: &mut Vec<u8>) -> Result<(), TpmDeviceError> {
        let state = self.0.borrow();
        buf.clear();
        buf.extend_from_slice(&state.pending);
        Ok(())
    }
}

fn device(state: State) -> (TpmDevice, Rc<RefCell<State>>) {
    let state = Rc::new(RefCell::new(state));
    let device = TpmDevice::new(Box::new(Simulator(Rc::clone(&state))));
    (device, state)
}

fn context() -> TpmsContext {
    TpmsContext {
        sequence: TpmUint64::new(1),
        saved_handle: TpmHandle::new(0x0300_0000),
        hierarchy: TpmRh::Owner,
        context_blob: Tpm2b::default(),
    }
}

fn error_rc() -> impl Strategy<Value = TpmRc> {
    prop_oneof![
        Just(TpmRc::Warn(TpmRcBase::ReferenceH0)),
        (1u8..=7).prop_map(|n| TpmRc::Fmt1(TpmRcFmt1 {
            base: TpmRcBase::Handle,
            index: Some(TpmRcIndex::Handle(n)),
        })),
        Just(TpmRc::Fmt1(TpmRcFmt1 {
            base: TpmRcBase::Handle,
            index: None,
        })),
        (1u32..0x1000).prop_filter_map("undefined response code", |raw| TpmRc::try_from(raw).ok()),
    ]
}

fn frame_strategy() -> impl Strategy<Value = Vec<u8>> {
    (
        any::<u16>(),
        any::<u32>(),
        prop::collection::vec(any::<u8>(), 0..=256),
    )
        .prop_map(|(tag, code, body)| frame(tag, code, &body))
}

proptest! {
    #![proptest_config(config(CASES))]

    #[test]
    fn frames_round_trip_over_streams(frames in prop::collection::vec(frame_strategy(), 1..6), tail in prop::collection::vec(any::<u8>(), 0..HEADER)) {
        let mut stream = Cursor::new(Vec::new());
        for frame in &frames {
            write_frame(&mut stream, frame).unwrap();
        }
        stream.get_mut().extend_from_slice(&tail);
        stream.set_position(0);

        let mut buf = vec![0xa5; 3];
        for frame in &frames {
            read_frame(&mut stream, &mut buf).unwrap();
            prop_assert_eq!(&buf, frame);
        }
        prop_assert_eq!(read_frame(&mut stream, &mut buf), Err(TpmDeviceError::UnexpectedEof));
    }

    #[test]
    fn read_frame_rejects_malformed_streams(frame in frame_strategy(), cut in any::<prop::sample::Index>(), size in any::<u32>()) {
        let len = cut.index(frame.len());
        let mut buf = Vec::new();
        prop_assert_eq!(
            read_frame(&mut Cursor::new(frame[..len].to_vec()), &mut buf),
            Err(TpmDeviceError::UnexpectedEof)
        );

        let mut resized = frame.clone();
        resized[2..6].copy_from_slice(&size.to_be_bytes());
        let size = usize::try_from(size).unwrap();
        let result = read_frame(&mut Cursor::new(resized.clone()), &mut buf);
        if !(HEADER..=TPM_MAX_COMMAND_SIZE).contains(&size) {
            prop_assert_eq!(result, Err(TpmDeviceError::InvalidResponse));
        } else if size > resized.len() {
            prop_assert_eq!(result, Err(TpmDeviceError::UnexpectedEof));
        } else {
            prop_assert_eq!(result, Ok(()));
            prop_assert_eq!(&buf[..], &resized[..size]);
        }
    }

    #[test]
    fn responder_serves_until_disconnect(commands in prop::collection::vec(frame_strategy(), 0..6)) {
        let input: Vec<u8> = commands.concat();
        let output = Rc::new(RefCell::new(Vec::new()));
        let transport = TpmStreamTransport::new(Duplex {
            input: Cursor::new(input),
            output: Rc::clone(&output),
        });
        let mut responder = TpmResponder::new(Box::new(transport));

        let mut served = Vec::new();
        responder
            .serve(|command| {
                served.push(command.to_vec());
                let mut response = command.to_vec();
                response.reverse();
                frame(0x8001, 0, &response)
            })
            .unwrap();

        prop_assert_eq!(&served, &commands);
        let expected: Vec<u8> = commands
            .iter()
            .flat_map(|c| {
                let mut response = c.clone();
                response.reverse();
                frame(0x8001, 0, &response)
            })
            .collect();
        prop_assert_eq!(&*output.borrow(), &expected);
    }

    #[test]
    fn fetch_handles_pages_through_all_handles(
        handles in prop::collection::btree_set(
            (prop::sample::select(vec![0x00u8, 0x01, 0x02, 0x03, 0x40, 0x80, 0x81, 0xff]), any::<u32>())
                .prop_map(|(ht, low)| (u32::from(ht) << 24) | (low & 0x00ff_ffff) | (u32::from(low % 4 == 0) * 0x00ff_ffff)),
            0..40,
        ),
        page in 1usize..=MAX_HANDLES,
        class in prop::sample::select(vec![TpmHt::Pcr, TpmHt::NvIndex, TpmHt::HmacSession, TpmHt::Permanent, TpmHt::Transient, TpmHt::Persistent]),
    ) {
        let all: Vec<u32> = handles.into_iter().collect();
        let (mut device, state) = device(State {
            handles: all.clone(),
            page,
            ..State::default()
        });

        let class_bits = u32::from(class.value());
        let expected: Vec<u32> = all.iter().copied().filter(|h| h >> 24 == class_bits).collect();
        let actual: Vec<u32> = device.fetch_handles(class).unwrap().iter().map(|h| h.value()).collect();
        prop_assert_eq!(actual, expected);

        let queries = state.borrow().capability_queries.clone();
        prop_assert_eq!(queries[0].0, class_bits << 24);
        prop_assert!(queries.iter().all(|q| q.1 == u32::try_from(MAX_HANDLES).unwrap()));
        prop_assert!(queries.windows(2).all(|w| w[0].0 < w[1].0));
    }

    #[test]
    fn flush_session_tolerates_missing_contexts(load in prop::option::of(error_rc()), loaded in any::<u32>()) {
        let (mut device, state) = device(State {
            load,
            loaded,
            ..State::default()
        });

        let result = device.flush_session(context());
        match load {
            None => {
                prop_assert_eq!(result, Ok(()));
                prop_assert_eq!(&state.borrow().flushed, &vec![loaded]);
            }
            Some(rc) if matches!(rc.base(), TpmRcBase::ReferenceH0 | TpmRcBase::Handle) => {
                prop_assert_eq!(result, Ok(()));
                prop_assert!(state.borrow().flushed.is_empty());
            }
            Some(rc) => {
                prop_assert_eq!(result, Err(TpmDeviceError::TpmRc(rc)));
                prop_assert!(state.borrow().flushed.is_empty());
            }
        }
    }

    #[test]
    fn transmit_reports_response_outcome(handle in any::<u32>(), rc in error_rc(), reply in prop::collection::vec(any::<u8>(), 0..32), raw in any::<bool>()) {
        let reply = if raw {
            reply
        } else {
            marshal_response(&TpmFlushContextResponse { handles: [] }, rc)
        };
        let (mut device, state) = device(State {
            reply: Some(reply.clone()),
            ..State::default()
        });

        let expected = match TpmResponse::cast(&reply)
            .and_then(|response| TpmResponseView::cast(TpmCc::FlushContext, response))
        {
            Err(err) => Err(TpmDeviceError::Unmarshal(err)),
            Ok(TpmResponseOutcome::Rejected(rc)) => Err(TpmDeviceError::TpmRc(rc)),
            Ok(TpmResponseOutcome::Dispatched(_)) => Ok(()),
        };
        prop_assert_eq!(device.flush_context(TpmHandle::new(handle)), expected);
        if !raw {
            prop_assert_eq!(device.flush_context(TpmHandle::new(handle)), Err(TpmDeviceError::TpmRc(rc)));
        }
        prop_assert!(state.borrow().flushed.is_empty());
    }

    #[test]
    fn with_device_guards_access(value in any::<u32>()) {
        let result: Result<u32, TpmDeviceError> = with_device(None, |_| Ok(value));
        prop_assert_eq!(result, Err(TpmDeviceError::NotAvailable));

        let (device, _) = device(State::default());
        let device = Rc::new(RefCell::new(device));
        prop_assert_eq!(with_device(Some(&device), |_| Ok::<_, TpmDeviceError>(value)), Ok(value));
        let _guard = device.borrow_mut();
        let result: Result<u32, TpmDeviceError> = with_device(Some(&device), |_| Ok(value));
        prop_assert_eq!(result, Err(TpmDeviceError::AlreadyBorrowed));
    }
}
