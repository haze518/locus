use std::{collections::VecDeque, time};

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
