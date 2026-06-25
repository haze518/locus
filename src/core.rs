use std::collections::VecDeque;

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::LogicalReplicationMessage;

pub enum MessageFormat {
    CopyBothResponse(CopyBothResponse),
    CopyData(CopyData),
    ErrorResponse(ErrorResponse),
    CommandComplete(CommandComplete),
    ReadyForQuery(ReadyForQuery),
}

pub struct CopyBothResponse {
    pub format: CopyFormat,
    pub column_formats: Vec<CopyFormat>,
}

pub enum CopyFormat {
    Text,
    Binary,
}

impl TryFrom<u16> for CopyFormat {
    type Error = anyhow::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Text),
            1 => Ok(Self::Binary),
            _ => Err(anyhow::bail!("unsupported format")),
        }
    }
}

pub trait PgOutputMessage: Sized {
    const TAG: u8;

    fn parse_body(buf: &mut Bytes) -> anyhow::Result<Self>;
}

impl PgOutputMessage for CopyBothResponse {
    const TAG: u8 = b'W';

    fn parse_body(buf: &mut Bytes) -> anyhow::Result<Self> {
        ensure_remaining(buf, 2 + 4)?;

        let format = CopyFormat::try_from(buf.get_u8() as u16)?;
        let column_formats_len = buf.get_u16();
        let mut column_formats = Vec::with_capacity(column_formats_len as usize);

        for _ in 0..column_formats_len {
            ensure_remaining(buf, 4)?;
            column_formats.push(CopyFormat::try_from(buf.get_u16())?);
        }

        Ok(Self {
            format,
            column_formats,
        })
    }
}

pub struct CopyData {
    pub payload: Bytes,
}

impl PgOutputMessage for CopyData {
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

impl PgOutputMessage for ErrorResponse {
    const TAG: u8 = b'E';

    fn parse_body(buf: &mut Bytes) -> anyhow::Result<Self> {
        Ok(Self {
            fields: buf.split_to(buf.remaining()),
        })
    }
}

pub struct CommandComplete {
    pub tag: String,
}

impl PgOutputMessage for CommandComplete {
    const TAG: u8 = b'C';

    fn parse_body(buf: &mut Bytes) -> anyhow::Result<Self> {
        let tag = read_cstring(buf)?;

        Ok(Self { tag })
    }
}

pub struct ReadyForQuery {
    pub tx_status: u8,
}

impl PgOutputMessage for ReadyForQuery {
    const TAG: u8 = b'Z';

    fn parse_body(buf: &mut Bytes) -> anyhow::Result<Self> {
        ensure_remaining(buf, 1)?;

        Ok(Self {
            tx_status: buf.get_u8(),
        })
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

pub enum ReplicationMessage {
    XlogData(XLogData),
    PrimaryKeepAlive(PrimaryKeepAlive),
}

pub struct XLogData {
    start_lsn: i64,
    end_lsn: i64,
    send_time: i64,
    wal_data: Bytes,
}

impl PgOutputMessage for XLogData {
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

impl PgOutputMessage for PrimaryKeepAlive {
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

fn parse_replication_message(mut payload: Bytes) -> anyhow::Result<ReplicationMessage> {
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

pub enum Event {
    Ready,
    ReplicationStarted,
    LogicalMessage(LogicalReplicationMessage),
    ServerError(String),
    Closed,
}

pub struct Core {
    data: BytesMut,
    ready: VecDeque<LogicalReplicationMessage>,
}

impl Core {
    pub fn handle(&mut self, raw: Bytes) -> anyhow::Result<()> {
        self.data.put_slice(&raw);
        loop {
            if self.data.len() < 5 {
                return Ok(());
            }

            let length = u32::from_be_bytes(self.data[1..5].try_into()?) as usize;

            if self.data.len() < 1 + length {
                return Ok(());
            }

            let data = self.data.split_to(length + 1).freeze();
            let msg = parse(data)?;
            match msg {
                MessageFormat::CopyData(d) => match parse_replication_message(d.payload)? {
                    ReplicationMessage::XlogData(v) => {
                        let lpm = crate::parse(v.wal_data)?;
                        self.ready.push_front(lpm);
                    }
                    ReplicationMessage::PrimaryKeepAlive(v) => {
                        todo!()
                    }
                },
                _ => return Ok(()),
            }
        }
    }
}

pub fn parse(mut payload: Bytes) -> anyhow::Result<MessageFormat> {
    ensure_remaining(&payload, 1)?;
    let tag = payload.get_u8();
    let length = payload.get_u32() as usize;

    let mut data = payload.split_to(1 + length);

    match tag {
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
        ReadyForQuery::TAG => {
            ReadyForQuery::parse_body(&mut data).map(MessageFormat::ReadyForQuery)
        }
        _ => anyhow::bail!("unsupported tag: {:?}", tag),
    }
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
