use std::{collections::VecDeque, net::SocketAddr, time};

use bytes::{BufMut, Bytes, BytesMut};

use crate::{
    LogicalReplicationMessage,
    auth::scram::ScramClient,
    backend::{
        self, Authentication, ErrorResponse, MessageFormat, PrimaryKeepAlive, ReplicationMessage,
    },
    protocol::{self, Codec},
    replication,
};

#[derive(Debug)]
enum CoreState {
    Startup,
    Authenticating(AuthState),
    Authenticated,
    Disconnected,
    Shutdown,
    StartReplication,
    Streaming,
    ClosingCopy,
    Failed,
}

#[derive(Debug)]
enum AuthState {
    None,
    Scram(ScramClient),
}

pub enum CoreEvent {
    LogicalMessage(LogicalReplicationMessage),
    KeepAlive(PrimaryKeepAlive),
    ReplicationStarted,
    ServerError(ErrorResponse),
    Connected,
}

pub struct ConnectParams {
    pub user_name: String,
    pub password: String,
    pub database: String,
    pub replication_mode: String,
    pub address: SocketAddr,
}

pub struct Core {
    state: CoreState,
    connect_params: Option<ConnectParams>,
    data: BytesMut,
    events: VecDeque<CoreEvent>,
    timeout: Option<time::Duration>,
    outgoing: VecDeque<Bytes>,
}

impl Core {
    pub fn new() -> Self {
        Self {
            state: CoreState::Disconnected,
            connect_params: None,
            data: BytesMut::new(),
            events: VecDeque::new(),
            timeout: None,
            outgoing: VecDeque::new(),
        }
    }

    pub fn desire_connect(&mut self, params: ConnectParams) -> anyhow::Result<()> {
        match self.state {
            CoreState::Shutdown => anyhow::bail!("client shutdown"),
            CoreState::ClosingCopy | CoreState::Failed => return Ok(()),
            CoreState::Startup
            | CoreState::Authenticating(_)
            | CoreState::Authenticated
            | CoreState::StartReplication
            | CoreState::Streaming => return Ok(()),
            CoreState::Disconnected => {
                let msg = protocol::StartupMessage {
                    user_name: params.user_name.clone(),
                    database: params.database.clone(),
                    replication: params.replication_mode.clone(),
                };
                self.connect_params = Some(params);
                self.outgoing.push_back(msg.encode()?);
                self.state = CoreState::Startup;
            }
        }
        Ok(())
    }

    pub fn close(&mut self) -> anyhow::Result<()> {
        match &mut self.state {
            CoreState::Disconnected | CoreState::Shutdown => Ok(()),
            CoreState::Streaming => {
                self.state = CoreState::ClosingCopy;
                let msg = protocol::CopyDone {};
                self.outgoing.push_back(msg.encode()?);
                Ok(())
            }
            CoreState::ClosingCopy => Ok(()),
            CoreState::Startup
            | CoreState::Authenticating(_)
            | CoreState::Authenticated
            | CoreState::StartReplication
            | CoreState::Failed => Ok(()),
        }
    }

    pub fn poll_write(&mut self) -> Option<Bytes> {
        self.outgoing.pop_front()
    }

    pub fn poll_timeout(&mut self) -> Option<time::Duration> {
        self.timeout.clone()
    }

    pub fn poll_event(&mut self) -> Option<CoreEvent> {
        self.events.pop_front()
    }

    pub fn handle(&mut self, raw: Bytes) -> anyhow::Result<()> {
        self.data.put_slice(&raw);
        loop {
            if self.data.len() < 5 {
                return Ok(());
            }

            let length = u32::from_be_bytes(self.data[1..5].try_into()?) as usize;
            if length < 4 {
                anyhow::bail!("invalid backend frame length: {length}");
            }
            if length > backend::MAX_FRAME_SIZE {
                anyhow::bail!("backend frame too large: {length} bytes");
            }

            if self.data.len() < 1 + length {
                return Ok(());
            }

            let data = self.data.split_to(length + 1).freeze();
            let msg = backend::parse(data)?;
            match msg {
                MessageFormat::CopyData(d) => {
                    if !matches!(self.state, CoreState::Streaming) {
                        anyhow::bail!("incorrect state: {:?}", self.state);
                    }

                    match backend::parse_replication_message(d.payload)? {
                        ReplicationMessage::XlogData(v) => {
                            let lpm = crate::parse(v.wal_data)?;
                            self.events.push_back(CoreEvent::LogicalMessage(lpm));
                        }
                        ReplicationMessage::PrimaryKeepAlive(v) => {
                            self.events.push_back(CoreEvent::KeepAlive(v));
                        }
                    }
                }
                MessageFormat::CopyBothResponse(_) => {
                    if matches!(self.state, CoreState::StartReplication) {
                        self.state = CoreState::Streaming;
                        self.events.push_back(CoreEvent::ReplicationStarted);
                    } else {
                        anyhow::bail!("incorrect state: {:?}", self.state);
                    }
                }
                MessageFormat::CommandComplete(_) => {
                    if !matches!(self.state, CoreState::ClosingCopy) {
                        anyhow::bail!("incorrect state: {:?}", self.state);
                    }
                }
                MessageFormat::ParameterStatus(_) | MessageFormat::BackendKeyData(_) => {}
                MessageFormat::ErrorResponse(e) => {
                    self.state = CoreState::Failed;
                    self.events.push_back(CoreEvent::ServerError(e));
                }
                MessageFormat::ReadyForQuery(_) => match &mut self.state {
                    CoreState::Authenticated => {
                        self.state = CoreState::StartReplication;
                        let msg = protocol::Query {
                            sql: replication::start_replication("locus"),
                        };
                        self.outgoing.push_back(msg.encode()?);
                        self.events.push_back(CoreEvent::Connected);
                    }
                    CoreState::ClosingCopy => {
                        self.state = CoreState::Disconnected;
                    }
                    _ => anyhow::bail!("incorrect state: {:?}", self.state),
                },
                MessageFormat::Authentication(a) => match a {
                    Authentication::Ok => {
                        self.state = CoreState::Authenticated;
                    }
                    Authentication::Sasl(s) => {
                        let params = self
                            .connect_params
                            .as_ref()
                            .ok_or_else(|| anyhow::anyhow!("unable to get connect_params"))?;

                        let scram_client = ScramClient::new(s.mechanisms, params.password.clone())?;
                        let msg = scram_client.initial_response();
                        self.outgoing.push_back(msg.encode()?);
                        let auth = AuthState::Scram(scram_client);
                        self.state = CoreState::Authenticating(auth)
                    }
                    Authentication::SaslContinue(s) => match &mut self.state {
                        CoreState::Authenticating(a) => match a {
                            AuthState::Scram(scram_client) => {
                                scram_client.handle_server_first(s.data)?;
                                let final_message = scram_client.final_response()?;
                                self.outgoing.push_back(final_message.encode()?);
                            }
                            _ => anyhow::bail!("incorrect authstate: {:?}", a),
                        },
                        _ => anyhow::bail!("incorrect state: {:?}", self.state),
                    },
                    Authentication::SaslFinal(f) => match &mut self.state {
                        CoreState::Authenticating(a) => match a {
                            AuthState::Scram(scram_client) => {
                                scram_client.handle_server_final(f.data)?;
                                self.state = CoreState::Authenticated;
                            }
                            _ => anyhow::bail!("incorrect authstate: {:?}", a),
                        },
                        _ => anyhow::bail!("incorrect state: {:?}", self.state),
                    },
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BufMut;

    fn backend_frame(tag: u8, body: &[u8]) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put_u8(tag);
        buf.put_u32((4 + body.len()) as u32);
        buf.put_slice(body);
        buf.freeze()
    }

    fn auth_ok() -> Bytes {
        let mut body = BytesMut::new();
        body.put_i32(0);
        backend_frame(b'R', &body)
    }

    fn ready_for_query() -> Bytes {
        backend_frame(b'Z', &[b'I'])
    }

    fn parameter_status(name: &str, value: &str) -> Bytes {
        let mut body = BytesMut::new();
        body.put_slice(name.as_bytes());
        body.put_u8(0);
        body.put_slice(value.as_bytes());
        body.put_u8(0);
        backend_frame(b'S', &body)
    }

    fn backend_key_data(pid: i32, secret: i32) -> Bytes {
        let mut body = BytesMut::new();
        body.put_i32(pid);
        body.put_i32(secret);
        backend_frame(b'K', &body)
    }

    fn copy_both_response() -> Bytes {
        let mut body = BytesMut::new();
        body.put_u16(0); // overall format: text
        body.put_u16(0); // zero column formats
        backend_frame(b'W', &body)
    }

    fn command_complete(tag: &str) -> Bytes {
        let mut body = BytesMut::new();
        body.put_slice(tag.as_bytes());
        body.put_u8(0);
        backend_frame(b'C', &body)
    }

    fn error_response() -> Bytes {
        backend_frame(b'E', &[0]) // empty field list (null terminator only)
    }

    fn connect_params() -> ConnectParams {
        ConnectParams {
            user_name: "test".into(),
            password: "test".into(),
            database: "test".into(),
            replication_mode: "database".into(),
        }
    }

    fn new_core_authenticated() -> Core {
        let mut core = Core::new();
        core.desire_connect(connect_params()).unwrap();
        core.poll_write(); // drain StartupMessage
        core.handle(auth_ok()).unwrap();
        core
    }

    fn new_core_start_replication() -> Core {
        let mut core = new_core_authenticated();
        core.handle(ready_for_query()).unwrap();
        core.poll_write(); // drain START_REPLICATION Query
        core.poll_event(); // drain Connected
        core
    }

    fn new_core_streaming() -> Core {
        let mut core = new_core_start_replication();
        core.handle(copy_both_response()).unwrap();
        core.poll_event(); // drain ReplicationStarted
        core
    }

    #[test]
    fn fragmented_frame_no_event_before_complete() {
        let mut core = Core::new();
        core.desire_connect(connect_params()).unwrap();
        core.poll_write(); // drain StartupMessage

        let frame = auth_ok(); // 9 bytes: [R, 0,0,0,8, 0,0,0,0]
        let mid = frame.len() / 2; // split at byte 4
        let first = frame.slice(..mid);
        let second = frame.slice(mid..);

        core.handle(first).unwrap();
        assert!(
            core.poll_event().is_none(),
            "no event before frame is complete"
        );
        assert!(
            core.poll_write().is_none(),
            "no output before frame is complete"
        );

        core.handle(second).unwrap();
        // auth_ok itself emits no event; validate state via RFQ
        core.handle(ready_for_query()).unwrap();
        assert!(
            core.poll_write().is_some(),
            "START_REPLICATION query must be queued after full frame processed"
        );
        assert!(
            matches!(core.poll_event(), Some(CoreEvent::Connected)),
            "Connected event must fire"
        );
    }

    #[test]
    fn multiple_frames_in_one_chunk_processed_in_order() {
        let mut core = Core::new();
        core.desire_connect(connect_params()).unwrap();
        core.poll_write(); // drain StartupMessage

        // Combine auth_ok + ready_for_query into a single Bytes.
        // Processing in order: Authenticated → StartReplication.
        let mut combined = BytesMut::new();
        combined.put_slice(&auth_ok());
        combined.put_slice(&ready_for_query());

        core.handle(combined.freeze()).unwrap();

        assert!(
            core.poll_write().is_some(),
            "START_REPLICATION query queued means both frames were processed in order"
        );
        assert!(matches!(core.poll_event(), Some(CoreEvent::Connected)));
    }

    fn auth_ok_then_ready_for_query_queues_start_replication() {
        let mut core = Core::new();
        core.desire_connect(connect_params()).unwrap();
        core.poll_write(); // drain StartupMessage

        core.handle(auth_ok()).unwrap();
        assert!(core.poll_event().is_none(), "no event after AuthOk alone");

        core.handle(ready_for_query()).unwrap();

        let write = core.poll_write().expect("expected Query frame");
        assert_eq!(write[0], b'Q', "frontend message must have Query tag");

        let length = u32::from_be_bytes(write[1..5].try_into().unwrap()) as usize;
        assert!(
            length >= 4,
            "length must include the 4-byte length field itself"
        );

        // body = SQL string + nul terminator
        let body = &write[5..5 + length - 4];
        assert_eq!(body.last(), Some(&0u8), "SQL must be nul-terminated");
        let sql = std::str::from_utf8(&body[..body.len() - 1]).unwrap();
        assert!(
            sql.contains("START_REPLICATION"),
            "Query must contain START_REPLICATION; got: {sql}"
        );

        assert!(
            matches!(core.poll_event(), Some(CoreEvent::Connected)),
            "Connected event must be emitted"
        );
    }

    #[test]
    fn parameter_status_and_backend_key_data_do_not_error() {
        let mut core = new_core_authenticated();

        core.handle(parameter_status("server_version", "16.0"))
            .unwrap();
        core.handle(backend_key_data(1234, 5678)).unwrap();

        assert!(core.poll_event().is_none());

        // State is still Authenticated; ReadyForQuery must still work.
        core.handle(ready_for_query()).unwrap();
        assert!(matches!(core.poll_event(), Some(CoreEvent::Connected)));
    }

    #[test]
    fn copy_both_response_emits_replication_started() {
        let mut core = new_core_start_replication();

        core.handle(copy_both_response()).unwrap();

        assert!(
            matches!(core.poll_event(), Some(CoreEvent::ReplicationStarted)),
            "ReplicationStarted must be emitted"
        );

        // Streaming state: benign no-op messages still accepted without error.
        core.handle(parameter_status("foo", "bar")).unwrap();
    }

    #[test]
    fn error_response_emits_server_error_and_poisons_state() {
        let mut core = Core::new();
        core.desire_connect(connect_params()).unwrap();
        core.poll_write();

        core.handle(error_response()).unwrap();

        assert!(
            matches!(core.poll_event(), Some(CoreEvent::ServerError(_))),
            "ServerError must be emitted"
        );

        // Core is now in Failed state; ReadyForQuery must be rejected.
        let result = core.handle(ready_for_query());
        assert!(
            result.is_err(),
            "messages after ServerError must not succeed silently"
        );
    }

    #[test]
    fn close_sends_copy_done_and_close_flow_completes() {
        let mut core = new_core_streaming();

        core.close().unwrap();

        let write = core.poll_write().expect("expected CopyDone frame");
        assert_eq!(
            &write[..],
            &[b'c', 0, 0, 0, 4],
            "CopyDone must be exactly [c, 0, 0, 0, 4]"
        );

        // Feed CommandComplete + ReadyForQuery to finish the close handshake.
        core.handle(command_complete("START_REPLICATION")).unwrap();
        core.handle(ready_for_query()).unwrap();

        assert!(core.poll_event().is_none(), "no events after clean close");
        assert!(
            core.poll_write().is_none(),
            "no pending output after clean close"
        );
    }
}
