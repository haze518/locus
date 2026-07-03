use bytes::{Buf, Bytes};

pub(crate) const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

pub(crate) enum MessageFormat {
    Authentication(Authentication),
    CopyBothResponse(CopyBothResponse),
    CopyData(CopyData),
    ErrorResponse(ErrorResponse),
    CommandComplete(CommandComplete),
    ParameterStatus(ParameterStatus),
    BackendKeyData(BackendKeyData),
    ReadyForQuery(ReadyForQuery),
}

pub(crate) enum Authentication {
    Ok,
    Sasl(AuthenticationSasl),
    SaslContinue(AuthenticationSaslContinue),
    SaslFinal(AuthenticationSaslFinal),
}

pub(crate) struct AuthenticationSasl {
    pub(crate) mechanisms: Vec<String>,
}

pub(crate) struct AuthenticationSaslContinue {
    pub(crate) data: Bytes,
}

pub(crate) struct AuthenticationSaslFinal {
    pub(crate) data: Bytes,
}

pub(crate) struct CopyBothResponse {
    pub(crate) format: CopyFormat,
    pub(crate) column_formats: Vec<CopyFormat>,
}

pub(crate) enum CopyFormat {
    Text,
    Binary,
}

impl TryFrom<u16> for CopyFormat {
    type Error = anyhow::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Text),
            1 => Ok(Self::Binary),
            _ => anyhow::bail!("unsupported format"),
        }
    }
}

pub(crate) trait BackendMessage: Sized {
    const TAG: u8;

    fn parse_body(buf: &mut Bytes) -> anyhow::Result<Self>;
}

impl BackendMessage for Authentication {
    const TAG: u8 = b'R';

    fn parse_body(buf: &mut Bytes) -> anyhow::Result<Self> {
        ensure_remaining(buf, 4)?;
        let auth_code = buf.get_i32();

        match auth_code {
            0 => Ok(Self::Ok),

            10 => {
                let mut mechanisms = Vec::new();

                while buf.remaining() > 0 {
                    let mechanism = read_cstring(buf)?;
                    if mechanism.is_empty() {
                        break;
                    }
                    mechanisms.push(mechanism);
                }

                Ok(Self::Sasl(AuthenticationSasl { mechanisms }))
            }

            11 => Ok(Self::SaslContinue(AuthenticationSaslContinue {
                data: buf.split_to(buf.remaining()),
            })),

            12 => Ok(Self::SaslFinal(AuthenticationSaslFinal {
                data: buf.split_to(buf.remaining()),
            })),

            other => anyhow::bail!("unsupported authentication code: {other}"),
        }
    }
}

impl BackendMessage for CopyBothResponse {
    const TAG: u8 = b'W';

    fn parse_body(buf: &mut Bytes) -> anyhow::Result<Self> {
        ensure_remaining(buf, 2 + 2)?;

        let format = CopyFormat::try_from(buf.get_u16())?;
        let column_formats_len = buf.get_u16();
        let mut column_formats = Vec::with_capacity(column_formats_len as usize);

        for _ in 0..column_formats_len {
            ensure_remaining(buf, 2)?;
            column_formats.push(CopyFormat::try_from(buf.get_u16())?);
        }

        Ok(Self {
            format,
            column_formats,
        })
    }
}

pub(crate) struct CopyData {
    pub(crate) payload: Bytes,
}

impl BackendMessage for CopyData {
    const TAG: u8 = b'd';

    fn parse_body(buf: &mut Bytes) -> anyhow::Result<Self> {
        Ok(Self {
            payload: buf.split_to(buf.remaining()),
        })
    }
}

pub struct ErrorResponse {
    pub fields: Bytes,
}

impl BackendMessage for ErrorResponse {
    const TAG: u8 = b'E';

    fn parse_body(buf: &mut Bytes) -> anyhow::Result<Self> {
        Ok(Self {
            fields: buf.split_to(buf.remaining()),
        })
    }
}

pub(crate) struct CommandComplete {
    pub(crate) tag: String,
}

impl BackendMessage for CommandComplete {
    const TAG: u8 = b'C';

    fn parse_body(buf: &mut Bytes) -> anyhow::Result<Self> {
        let tag = read_cstring(buf)?;

        Ok(Self { tag })
    }
}

pub(crate) struct ParameterStatus {
    pub(crate) name: String,
    pub(crate) value: String,
}

impl BackendMessage for ParameterStatus {
    const TAG: u8 = b'S';

    fn parse_body(buf: &mut Bytes) -> anyhow::Result<Self> {
        let name = read_cstring(buf)?;
        let value = read_cstring(buf)?;

        Ok(Self { name, value })
    }
}

pub(crate) struct BackendKeyData {
    pub(crate) process_id: i32,
    pub(crate) secret_key: i32,
}

impl BackendMessage for BackendKeyData {
    const TAG: u8 = b'K';

    fn parse_body(buf: &mut Bytes) -> anyhow::Result<Self> {
        ensure_remaining(buf, 8)?;

        Ok(Self {
            process_id: buf.get_i32(),
            secret_key: buf.get_i32(),
        })
    }
}

pub(crate) struct ReadyForQuery {
    pub(crate) tx_status: u8,
}

impl BackendMessage for ReadyForQuery {
    const TAG: u8 = b'Z';

    fn parse_body(buf: &mut Bytes) -> anyhow::Result<Self> {
        ensure_remaining(buf, 1)?;

        Ok(Self {
            tx_status: buf.get_u8(),
        })
    }
}

pub(crate) enum ReplicationMessage {
    XlogData(XLogData),
    PrimaryKeepAlive(PrimaryKeepAlive),
}

pub(crate) struct XLogData {
    start_lsn: i64,
    end_lsn: i64,
    send_time: i64,
    pub(crate) wal_data: Bytes,
}

impl BackendMessage for XLogData {
    const TAG: u8 = b'w';

    fn parse_body(buf: &mut Bytes) -> anyhow::Result<Self> {
        ensure_remaining(buf, 8 + 8 + 8)?;
        Ok(Self {
            start_lsn: buf.get_i64(),
            end_lsn: buf.get_i64(),
            send_time: buf.get_i64(),
            wal_data: buf.split_to(buf.remaining()),
        })
    }
}

pub struct PrimaryKeepAlive {
    end_lsn: i64,
    send_time: i64,
    reply_requested: i8,
}

impl BackendMessage for PrimaryKeepAlive {
    const TAG: u8 = b'k';

    fn parse_body(buf: &mut Bytes) -> anyhow::Result<Self> {
        ensure_remaining(buf, 8 + 8 + 1)?;
        Ok(Self {
            end_lsn: buf.get_i64(),
            send_time: buf.get_i64(),
            reply_requested: buf.get_i8(),
        })
    }
}

pub(crate) fn parse_replication_message(mut payload: Bytes) -> anyhow::Result<ReplicationMessage> {
    ensure_remaining(&payload, 1)?;
    let tag = payload.get_u8();

    match tag {
        XLogData::TAG => XLogData::parse_body(&mut payload).map(ReplicationMessage::XlogData),
        PrimaryKeepAlive::TAG => {
            PrimaryKeepAlive::parse_body(&mut payload).map(ReplicationMessage::PrimaryKeepAlive)
        }
        other => anyhow::bail!("unsupported pgoutput message tag: {:?}", other),
    }
}

pub(crate) fn parse(mut payload: Bytes) -> anyhow::Result<MessageFormat> {
    ensure_remaining(&payload, 5)?;
    let tag = payload.get_u8();
    let length = payload.get_u32() as usize;

    if length < 4 {
        anyhow::bail!("invalid backend frame length: {length}");
    }
    if length > MAX_FRAME_SIZE {
        anyhow::bail!("backend frame too large: {length} bytes");
    }

    let body_len = length - 4;
    ensure_remaining(&payload, body_len)?;
    let mut data = payload.split_to(body_len);

    match tag {
        Authentication::TAG => {
            Authentication::parse_body(&mut data).map(MessageFormat::Authentication)
        }
        CopyBothResponse::TAG => {
            CopyBothResponse::parse_body(&mut data).map(MessageFormat::CopyBothResponse)
        }
        CopyData::TAG => CopyData::parse_body(&mut data).map(MessageFormat::CopyData),
        ErrorResponse::TAG => {
            ErrorResponse::parse_body(&mut data).map(MessageFormat::ErrorResponse)
        }
        CommandComplete::TAG => {
            CommandComplete::parse_body(&mut data).map(MessageFormat::CommandComplete)
        }
        ParameterStatus::TAG => {
            ParameterStatus::parse_body(&mut data).map(MessageFormat::ParameterStatus)
        }
        BackendKeyData::TAG => {
            BackendKeyData::parse_body(&mut data).map(MessageFormat::BackendKeyData)
        }
        ReadyForQuery::TAG => {
            ReadyForQuery::parse_body(&mut data).map(MessageFormat::ReadyForQuery)
        }
        _ => anyhow::bail!("unsupported tag: {:?}", tag),
    }
}

fn ensure_remaining(buf: &Bytes, required: usize) -> anyhow::Result<()> {
    if buf.remaining() < required {
        anyhow::bail!(
            "unexpected EOF: need {} bytes, have {}",
            required,
            buf.remaining()
        );
    }

    Ok(())
}

fn read_cstring(buf: &mut Bytes) -> anyhow::Result<String> {
    let nul_pos = buf
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| anyhow::anyhow!("cstring terminator not found"))?;

    let raw = buf.split_to(nul_pos);
    buf.advance(1);

    Ok(String::from_utf8(raw.to_vec())?)
}
