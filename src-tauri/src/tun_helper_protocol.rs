use std::{
    fmt,
    io::{Read, Write},
};

use serde::{Deserialize, Serialize};

pub(crate) const PROTOCOL_VERSION: u16 = 3;
pub(crate) const MAX_FRAME_BYTES: usize = 32 * 1024;
pub(crate) const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Frame {
    HelperHello {
        protocol_version: u16,
        session: String,
        helper_pid: u32,
        helper_created: u64,
        nonce: String,
    },
    GuiChallenge {
        protocol_version: u16,
        session: String,
        request_id: u64,
        challenge: String,
        expires_at: u64,
    },
    StartTun {
        protocol_version: u16,
        session: String,
        request_id: u64,
        challenge: String,
        hello_nonce: String,
        config_handle_id: u64,
        config_len: u64,
        config_sha256: String,
        preflight_sha256: String,
        upstream_choice: UpstreamChoice,
    },
    Started {
        request_id: u64,
        engine_pid: u32,
        engine_created: u64,
    },
    StopTun {
        protocol_version: u16,
        session: String,
        request_id: u64,
    },
    Stopped {
        request_id: u64,
        cleanup: CleanupState,
    },
    Status {
        protocol_version: u16,
        session: String,
        request_id: u64,
    },
    State {
        request_id: u64,
        phase: HelperPhase,
        engine_pid: Option<u32>,
        cleanup: CleanupState,
        capture: Option<TunInterfaceState>,
    },
    Failure {
        request_id: u64,
        code: HelperFailureCode,
        safe_detail: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TunInterfaceState {
    pub interface_luid: u64,
    pub in_octets: u64,
    pub out_octets: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum UpstreamChoice {
    Physical {
        interface_luid: u64,
        interface_index: u32,
        interface_alias: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HelperPhase {
    Starting,
    Running,
    Stopping,
    Stopped,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CleanupState {
    NotRequired,
    Complete,
    Conflict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HelperFailureCode {
    ProtocolRejected,
    ParentRejected,
    ConfigRejected,
    EngineRejected,
    PreflightConflict,
    CaptureInvalid,
    StartFailed,
    StopFailed,
    CleanupConflict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProtocolError(&'static str);

impl ProtocolError {
    fn new(message: &'static str) -> Self {
        Self(message)
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for ProtocolError {}

pub(crate) fn write_frame(writer: &mut impl Write, frame: &Frame) -> Result<(), ProtocolError> {
    validate_frame(frame)?;
    let payload = serde_json::to_vec(frame)
        .map_err(|_| ProtocolError::new("could not encode helper frame"))?;
    if payload.is_empty() || payload.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::new("helper frame exceeds the size limit"));
    }
    writer
        .write_all(&(payload.len() as u32).to_le_bytes())
        .and_then(|_| writer.write_all(&payload))
        .and_then(|_| writer.flush())
        .map_err(|_| ProtocolError::new("could not write helper frame"))
}

pub(crate) fn read_frame(reader: &mut impl Read) -> Result<Frame, ProtocolError> {
    let mut length = [0_u8; 4];
    reader
        .read_exact(&mut length)
        .map_err(|_| ProtocolError::new("could not read helper frame length"))?;
    let length = u32::from_le_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(ProtocolError::new("helper frame exceeds the size limit"));
    }
    let mut payload = vec![0_u8; length];
    reader
        .read_exact(&mut payload)
        .map_err(|_| ProtocolError::new("could not read complete helper frame"))?;
    let mut deserializer = serde_json::Deserializer::from_slice(&payload);
    let frame = Frame::deserialize(&mut deserializer)
        .map_err(|_| ProtocolError::new("helper frame schema is invalid"))?;
    deserializer
        .end()
        .map_err(|_| ProtocolError::new("helper frame has trailing data"))?;
    validate_frame(&frame)?;
    Ok(frame)
}

pub(crate) fn validate_frame(frame: &Frame) -> Result<(), ProtocolError> {
    match frame {
        Frame::HelperHello {
            protocol_version,
            session,
            helper_pid,
            helper_created,
            nonce,
        } => {
            version(*protocol_version)?;
            session_id(session)?;
            nonzero(*helper_pid as u64)?;
            nonzero(*helper_created)?;
            exact_hex(nonce, 64)?;
        }
        Frame::GuiChallenge {
            protocol_version,
            session,
            request_id,
            challenge,
            expires_at,
        } => {
            version(*protocol_version)?;
            session_id(session)?;
            nonzero(*request_id)?;
            exact_hex(challenge, 64)?;
            nonzero(*expires_at)?;
        }
        Frame::StartTun {
            protocol_version,
            session,
            request_id,
            challenge,
            hello_nonce,
            config_handle_id,
            config_len,
            config_sha256,
            preflight_sha256,
            upstream_choice,
        } => {
            version(*protocol_version)?;
            session_id(session)?;
            nonzero(*request_id)?;
            exact_hex(challenge, 64)?;
            exact_hex(hello_nonce, 64)?;
            nonzero(*config_handle_id)?;
            if *config_len == 0 || *config_len > MAX_CONFIG_BYTES {
                return Err(ProtocolError::new("helper config length is invalid"));
            }
            exact_hex(config_sha256, 64)?;
            exact_hex(preflight_sha256, 64)?;
            match upstream_choice {
                UpstreamChoice::Physical {
                    interface_luid,
                    interface_index,
                    interface_alias,
                } => {
                    nonzero(*interface_luid)?;
                    nonzero(*interface_index as u64)?;
                    if interface_alias.is_empty()
                        || interface_alias.encode_utf16().count() > 256
                        || interface_alias.chars().any(char::is_control)
                    {
                        return Err(ProtocolError::new(
                            "helper upstream interface identity is invalid",
                        ));
                    }
                }
            }
        }
        Frame::Started {
            request_id,
            engine_pid,
            engine_created,
        } => {
            nonzero(*request_id)?;
            nonzero(*engine_pid as u64)?;
            nonzero(*engine_created)?;
        }
        Frame::StopTun {
            protocol_version,
            session,
            request_id,
        }
        | Frame::Status {
            protocol_version,
            session,
            request_id,
        } => {
            version(*protocol_version)?;
            session_id(session)?;
            nonzero(*request_id)?;
        }
        Frame::Stopped { request_id, .. } | Frame::Failure { request_id, .. } => {
            nonzero(*request_id)?
        }
        Frame::State {
            request_id,
            phase,
            engine_pid,
            capture,
            ..
        } => {
            nonzero(*request_id)?;
            let running = *phase == HelperPhase::Running;
            if running != engine_pid.is_some() || running != capture.is_some() {
                return Err(ProtocolError::new(
                    "helper running state proof is incomplete",
                ));
            }
            if capture
                .as_ref()
                .is_some_and(|state| state.interface_luid == 0)
            {
                return Err(ProtocolError::new(
                    "helper TUN interface identity is invalid",
                ));
            }
        }
    }
    if let Frame::Failure { safe_detail, .. } = frame {
        if safe_detail.as_ref().is_some_and(|detail| {
            detail.len() > 512 || detail.chars().any(|character| character.is_control())
        }) {
            return Err(ProtocolError::new("helper failure detail is invalid"));
        }
    }
    Ok(())
}

fn version(version: u16) -> Result<(), ProtocolError> {
    if version == PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(ProtocolError::new("helper protocol version is unsupported"))
    }
}

pub(crate) fn session_id(value: &str) -> Result<(), ProtocolError> {
    exact_hex(value, 32)
}

pub(crate) fn pipe_suffix(value: &str) -> Result<(), ProtocolError> {
    exact_hex(value, 32)
}

pub(crate) fn exact_hex(value: &str, length: usize) -> Result<(), ProtocolError> {
    if value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ProtocolError::new("helper identifier is invalid"))
    }
}

fn nonzero(value: u64) -> Result<(), ProtocolError> {
    if value == 0 {
        Err(ProtocolError::new("helper numeric identifier is invalid"))
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServerState {
    AwaitingChallenge,
    AwaitingStart { request_id: u64 },
    Running { last_request_id: u64 },
    Stopped { last_request_id: u64 },
}

impl ServerState {
    pub(crate) fn accept(&mut self, frame: &Frame) -> Result<(), ProtocolError> {
        validate_frame(frame)?;
        match (*self, frame) {
            (Self::AwaitingChallenge, Frame::GuiChallenge { request_id, .. }) => {
                *self = Self::AwaitingStart {
                    request_id: *request_id,
                };
                Ok(())
            }
            (
                Self::AwaitingStart { request_id },
                Frame::StartTun {
                    request_id: next, ..
                },
            ) if *next > request_id => {
                *self = Self::Running {
                    last_request_id: *next,
                };
                Ok(())
            }
            (
                Self::Running { last_request_id },
                Frame::Status {
                    request_id: next, ..
                },
            ) if *next > last_request_id => {
                *self = Self::Running {
                    last_request_id: *next,
                };
                Ok(())
            }
            (
                Self::Running { last_request_id },
                Frame::StopTun {
                    request_id: next, ..
                },
            ) if *next > last_request_id => {
                *self = Self::Stopped {
                    last_request_id: *next,
                };
                Ok(())
            }
            (
                Self::Stopped { last_request_id },
                Frame::StopTun {
                    request_id: next, ..
                },
            ) if *next > last_request_id => {
                *self = Self::Stopped {
                    last_request_id: *next,
                };
                Ok(())
            }
            _ => Err(ProtocolError::new(
                "helper frame is invalid in the current state",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn start(request_id: u64) -> Frame {
        Frame::StartTun {
            protocol_version: PROTOCOL_VERSION,
            session: "01".repeat(16),
            request_id,
            challenge: "02".repeat(32),
            hello_nonce: "03".repeat(32),
            config_handle_id: 42,
            config_len: 128,
            config_sha256: "04".repeat(32),
            preflight_sha256: "05".repeat(32),
            upstream_choice: UpstreamChoice::Physical {
                interface_luid: 7,
                interface_index: 9,
                interface_alias: "Ethernet".into(),
            },
        }
    }

    #[test]
    fn frames_round_trip_with_a_bounded_length_prefix() {
        let frame = start(2);
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &frame).unwrap();
        assert!(bytes.len() < MAX_FRAME_BYTES);
        assert_eq!(read_frame(&mut Cursor::new(bytes)).unwrap(), frame);

        let state = Frame::State {
            request_id: 3,
            phase: HelperPhase::Running,
            engine_pid: Some(42),
            cleanup: CleanupState::NotRequired,
            capture: Some(TunInterfaceState {
                interface_luid: 7,
                in_octets: 1024,
                out_octets: 2048,
            }),
        };
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &state).unwrap();
        assert_eq!(read_frame(&mut Cursor::new(bytes)).unwrap(), state);
    }

    #[test]
    fn oversized_zero_and_incomplete_frames_are_rejected() {
        assert!(read_frame(&mut Cursor::new(0_u32.to_le_bytes())).is_err());
        assert!(read_frame(&mut Cursor::new(
            ((MAX_FRAME_BYTES + 1) as u32).to_le_bytes()
        ))
        .is_err());
        let mut incomplete = 12_u32.to_le_bytes().to_vec();
        incomplete.extend_from_slice(b"{}");
        assert!(read_frame(&mut Cursor::new(incomplete)).is_err());
    }

    #[test]
    fn unknown_duplicate_and_trailing_fields_are_rejected() {
        for json in [
            r#"{"type":"status","protocol_version":1,"session":"01010101010101010101010101010101","request_id":1,"extra":true}"#,
            r#"{"type":"status","protocol_version":1,"session":"01010101010101010101010101010101","request_id":1,"request_id":2}"#,
        ] {
            let mut bytes = (json.len() as u32).to_le_bytes().to_vec();
            bytes.extend_from_slice(json.as_bytes());
            assert!(read_frame(&mut Cursor::new(bytes)).is_err());
        }
        let json = r#"{"type":"status","protocol_version":1,"session":"01010101010101010101010101010101","request_id":1} null"#;
        let mut bytes = (json.len() as u32).to_le_bytes().to_vec();
        bytes.extend_from_slice(json.as_bytes());
        assert!(read_frame(&mut Cursor::new(bytes)).is_err());
    }

    #[test]
    fn identifiers_and_config_bounds_are_strict() {
        let mut frame = start(2);
        if let Frame::StartTun {
            session,
            config_len,
            ..
        } = &mut frame
        {
            *session = "A".repeat(32);
            *config_len = MAX_CONFIG_BYTES + 1;
        }
        assert!(validate_frame(&frame).is_err());
        assert!(pipe_suffix("../helper").is_err());

        assert!(validate_frame(&Frame::State {
            request_id: 1,
            phase: HelperPhase::Running,
            engine_pid: Some(42),
            cleanup: CleanupState::NotRequired,
            capture: Some(TunInterfaceState {
                interface_luid: 0,
                in_octets: 0,
                out_octets: 0,
            }),
        })
        .is_err());
    }

    #[test]
    fn physical_upstream_identity_is_nonzero_bounded_and_control_free() {
        let mut frame = start(2);
        if let Frame::StartTun {
            upstream_choice:
                UpstreamChoice::Physical {
                    interface_luid,
                    interface_alias,
                    ..
                },
            ..
        } = &mut frame
        {
            *interface_luid = 0;
            *interface_alias = "Ethernet\nspoofed".into();
        }
        assert!(validate_frame(&frame).is_err());

        let mut frame = start(2);
        if let Frame::StartTun {
            upstream_choice:
                UpstreamChoice::Physical {
                    interface_alias, ..
                },
            ..
        } = &mut frame
        {
            *interface_alias = "x".repeat(257);
        }
        assert!(validate_frame(&frame).is_err());
    }

    #[test]
    fn state_machine_rejects_replay_second_start_and_out_of_order_stop() {
        let session = "01".repeat(16);
        let challenge = Frame::GuiChallenge {
            protocol_version: PROTOCOL_VERSION,
            session: session.clone(),
            request_id: 1,
            challenge: "02".repeat(32),
            expires_at: 100,
        };
        let mut state = ServerState::AwaitingChallenge;
        assert!(state.accept(&start(2)).is_err());
        state.accept(&challenge).unwrap();
        state.accept(&start(2)).unwrap();
        assert!(state.accept(&start(3)).is_err());
        let replay = Frame::Status {
            protocol_version: PROTOCOL_VERSION,
            session: session.clone(),
            request_id: 2,
        };
        assert!(state.accept(&replay).is_err());
        let stop = Frame::StopTun {
            protocol_version: PROTOCOL_VERSION,
            session,
            request_id: 3,
        };
        state.accept(&stop).unwrap();
        assert!(matches!(state, ServerState::Stopped { .. }));
    }
}
