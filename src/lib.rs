mod codec;
mod core;
mod driver;

use bytes::{Buf, Bytes};

pub enum LogicalReplicationMessage {
    Begin(Begin),
    Message(Message),
    Commit(Commit),
    Origin(Origin),
    Relation(Relation),
    Type(Type),
    Insert(Insert),
    Update(Update),
    Delete(Delete),
    Truncate(Truncate),
    StreamStart(StreamStart),
    StreamStop(StreamStop),
    StreamCommit(StreamCommit),
    StreamAbort(StreamAbort),
}

pub struct Begin {
    pub final_lsn: i64,
    pub commit_timestamp: i64,
    pub xid: i32,
}

pub struct Message {
    pub xid: Option<i32>, // only protocol v2 streamed transactions
    pub flags: i8,
    pub lsn: i64,
    pub prefix: String,
    pub content: Bytes,
}

pub struct Commit {
    pub flags: i8, // currently unused
    pub commit_lsn: i64,
    pub end_lsn: i64,
    pub commit_timestamp: i64,
}

pub struct Origin {
    pub commit_lsn: i64,
    pub name: String,
}

pub struct Relation {
    pub xid: Option<i32>, // protocol v2 streamed transactions
    pub relation_id: i32,
    pub namespace: String,
    pub name: String,
    pub replica_identity: i8,
    pub columns: Vec<Column>,
}

pub struct Type {
    pub xid: Option<i32>, // protocol v2 streamed transactions
    pub type_id: i32,
    pub namespace: String,
    pub name: String,
}

pub struct Insert {
    pub xid: Option<i32>,
    pub relation_id: i32,
    pub new_tuple: TupleData,
}

pub struct Update {
    pub xid: Option<i32>,
    pub relation_id: i32,
    pub old_tuple: Option<OldTuple>,
    pub new_tuple: TupleData,
}

pub struct Delete {
    pub xid: Option<i32>,
    pub relation_id: i32,
    pub old_tuple: OldTuple,
}

pub struct Truncate {
    pub xid: Option<i32>,
    pub relation_ids: Vec<i32>,
    pub options: TruncateOptions,
}

pub struct StreamStart {
    pub xid: i32,
    pub first_segment: bool,
}

pub struct StreamStop;

pub struct StreamCommit {
    pub xid: i32,
    pub flags: i8,
    pub commit_lsn: i64,
    pub end_lsn: i64,
    pub commit_timestamp: i64,
}

pub struct StreamAbort {
    pub xid: i32,
    pub subxid: i32,
}

pub struct Column {
    pub flags: i8, // 1 = key column
    pub name: String,
    pub type_id: i32,
    pub type_modifier: i32,
}

pub struct TupleData {
    pub columns: Vec<TupleValue>,
}

pub enum TupleValue {
    Null,
    UnchangedToast,
    Text(Bytes),
}

pub enum OldTuple {
    Key(TupleData), // 'K'
    Old(TupleData), // 'O'
}

pub struct TruncateOptions {
    pub cascade: bool,
    pub restart_identity: bool,
}

pub trait PgOutputMessage: Sized {
    const TAG: u8;

    fn parse_body(buf: &mut Bytes) -> anyhow::Result<Self>;
}

impl PgOutputMessage for Begin {
    const TAG: u8 = b'B';

    fn parse_body(buf: &mut Bytes) -> anyhow::Result<Self> {
        ensure_remaining(buf, 8 + 8 + 4)?;

        Ok(Begin {
            final_lsn: buf.get_i64(),
            commit_timestamp: buf.get_i64(),
            xid: buf.get_i32(),
        })
    }
}

impl PgOutputMessage for Commit {
    const TAG: u8 = b'C';

    fn parse_body(buf: &mut Bytes) -> anyhow::Result<Self> {
        ensure_remaining(buf, 1 + 8 + 8 + 8 + 8)?;

        Ok(Commit {
            flags: buf.get_i8(),
            commit_lsn: buf.get_i64(),
            end_lsn: buf.get_i64(),
            commit_timestamp: buf.get_i64(),
        })
    }
}

impl PgOutputMessage for Origin {
    const TAG: u8 = b'O';

    fn parse_body(buf: &mut Bytes) -> anyhow::Result<Self> {
        ensure_remaining(buf, 8)?;

        Ok(Origin {
            commit_lsn: buf.get_i64(),
            name: read_cstring(buf)?,
        })
    }
}

impl PgOutputMessage for Relation {
    const TAG: u8 = b'R';

    fn parse_body(buf: &mut Bytes) -> anyhow::Result<Self> {
        ensure_remaining(buf, 4)?;
        let relation_id = buf.get_i32();

        let namespace = read_cstring(buf)?;
        let name = read_cstring(buf)?;

        ensure_remaining(buf, 1 + 2)?;
        let replica_identity = buf.get_i8();
        let column_count = buf.get_i16() as usize;

        let mut columns = Vec::with_capacity(column_count);
        for _ in 0..column_count {
            ensure_remaining(buf, 1)?;
            let flags = buf.get_i8();

            let name = read_cstring(buf)?;

            ensure_remaining(buf, 4 + 4)?;
            columns.push(Column {
                flags,
                name,
                type_id: buf.get_i32(),
                type_modifier: buf.get_i32(),
            });
        }

        Ok(Relation {
            xid: None,
            relation_id,
            namespace,
            name,
            replica_identity,
            columns,
        })
    }
}

impl PgOutputMessage for Type {
    const TAG: u8 = b'Y';

    fn parse_body(buf: &mut Bytes) -> anyhow::Result<Self> {
        ensure_remaining(buf, 4)?;
        let type_id = buf.get_i32();

        Ok(Type {
            xid: None,
            type_id,
            namespace: read_cstring(buf)?,
            name: read_cstring(buf)?,
        })
    }
}

impl PgOutputMessage for Insert {
    const TAG: u8 = b'I';

    fn parse_body(buf: &mut Bytes) -> anyhow::Result<Self> {
        ensure_remaining(buf, 4 + 1)?;
        let relation_id = buf.get_i32();
        let tuple_tag = buf.get_u8();

        if tuple_tag != b'N' {
            anyhow::bail!("expected new tuple tag 'N', got {:?}", tuple_tag as char);
        }

        Ok(Insert {
            xid: None,
            relation_id,
            new_tuple: read_tuple_data(buf)?,
        })
    }
}

impl PgOutputMessage for Update {
    const TAG: u8 = b'U';

    fn parse_body(buf: &mut Bytes) -> anyhow::Result<Self> {
        ensure_remaining(buf, 4 + 1)?;
        let relation_id = buf.get_i32();
        let tuple_tag = buf.get_u8();

        let old_tuple = match tuple_tag {
            b'K' => Some(OldTuple::Key(read_tuple_data(buf)?)),
            b'O' => Some(OldTuple::Old(read_tuple_data(buf)?)),
            b'N' => None,
            other => anyhow::bail!("unexpected update tuple tag {:?}", other as char),
        };

        let new_tuple = if tuple_tag == b'N' {
            read_tuple_data(buf)?
        } else {
            ensure_remaining(buf, 1)?;
            let next_tag = buf.get_u8();

            if next_tag != b'N' {
                anyhow::bail!("expected new tuple tag 'N', got {:?}", next_tag as char);
            }

            read_tuple_data(buf)?
        };

        Ok(Update {
            xid: None,
            relation_id,
            old_tuple,
            new_tuple,
        })
    }
}

impl PgOutputMessage for Delete {
    const TAG: u8 = b'D';

    fn parse_body(buf: &mut Bytes) -> anyhow::Result<Self> {
        ensure_remaining(buf, 4 + 1)?;
        let relation_id = buf.get_i32();
        let tuple_tag = buf.get_u8();

        let old_tuple = match tuple_tag {
            b'K' => OldTuple::Key(read_tuple_data(buf)?),
            b'O' => OldTuple::Old(read_tuple_data(buf)?),
            other => anyhow::bail!("unexpected delete tuple tag {:?}", other as char),
        };

        Ok(Delete {
            xid: None,
            relation_id,
            old_tuple,
        })
    }
}

impl PgOutputMessage for Truncate {
    const TAG: u8 = b'T';

    fn parse_body(buf: &mut Bytes) -> anyhow::Result<Self> {
        ensure_remaining(buf, 4 + 1)?;
        let relation_count = buf.get_i32() as usize;
        let raw_options = buf.get_u8();

        ensure_remaining(buf, relation_count * 4)?;

        let mut relation_ids = Vec::with_capacity(relation_count);
        for _ in 0..relation_count {
            relation_ids.push(buf.get_i32());
        }

        Ok(Truncate {
            xid: None,
            relation_ids,
            options: TruncateOptions {
                cascade: raw_options & 0b0000_0001 != 0,
                restart_identity: raw_options & 0b0000_0010 != 0,
            },
        })
    }
}

impl PgOutputMessage for Message {
    const TAG: u8 = b'M';

    fn parse_body(buf: &mut Bytes) -> anyhow::Result<Self> {
        ensure_remaining(buf, 1 + 8)?;
        let flags = buf.get_i8();
        let lsn = buf.get_i64();
        let prefix = read_cstring(buf)?;

        ensure_remaining(buf, 4)?;
        let content_len = buf.get_i32() as usize;

        ensure_remaining(buf, content_len)?;
        let content = buf.split_to(content_len);

        Ok(Message {
            xid: None,
            flags,
            lsn,
            prefix,
            content,
        })
    }
}

impl PgOutputMessage for StreamStart {
    const TAG: u8 = b'S';

    fn parse_body(buf: &mut Bytes) -> anyhow::Result<Self> {
        ensure_remaining(buf, 4 + 1)?;

        Ok(StreamStart {
            xid: buf.get_i32(),
            first_segment: buf.get_u8() != 0,
        })
    }
}

impl PgOutputMessage for StreamStop {
    const TAG: u8 = b'E';

    fn parse_body(_buf: &mut Bytes) -> anyhow::Result<Self> {
        Ok(StreamStop)
    }
}

impl PgOutputMessage for StreamCommit {
    const TAG: u8 = b'c';

    fn parse_body(buf: &mut Bytes) -> anyhow::Result<Self> {
        ensure_remaining(buf, 4 + 1 + 8 + 8 + 8)?;

        Ok(StreamCommit {
            xid: buf.get_i32(),
            flags: buf.get_i8(),
            commit_lsn: buf.get_i64(),
            end_lsn: buf.get_i64(),
            commit_timestamp: buf.get_i64(),
        })
    }
}

impl PgOutputMessage for StreamAbort {
    const TAG: u8 = b'A';

    fn parse_body(buf: &mut Bytes) -> anyhow::Result<Self> {
        ensure_remaining(buf, 4 + 4)?;

        Ok(StreamAbort {
            xid: buf.get_i32(),
            subxid: buf.get_i32(),
        })
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

fn read_tuple_data(buf: &mut Bytes) -> anyhow::Result<TupleData> {
    ensure_remaining(buf, 2)?;
    let column_count = buf.get_i16() as usize;

    let mut columns = Vec::with_capacity(column_count);

    for _ in 0..column_count {
        ensure_remaining(buf, 1)?;
        let tag = buf.get_u8();

        let value = match tag {
            b'n' => TupleValue::Null,
            b'u' => TupleValue::UnchangedToast,
            b't' => {
                ensure_remaining(buf, 4)?;
                let len = buf.get_i32() as usize;

                ensure_remaining(buf, len)?;
                TupleValue::Text(buf.split_to(len))
            }
            other => anyhow::bail!("unsupported tuple value tag {:?}", other as char),
        };

        columns.push(value);
    }

    Ok(TupleData { columns })
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

pub fn parse(mut payload: Bytes) -> anyhow::Result<LogicalReplicationMessage> {
    ensure_remaining(&payload, 1)?;
    let tag = payload.get_u8();

    match tag {
        Begin::TAG => Begin::parse_body(&mut payload).map(LogicalReplicationMessage::Begin),
        Message::TAG => Message::parse_body(&mut payload).map(LogicalReplicationMessage::Message),
        Commit::TAG => Commit::parse_body(&mut payload).map(LogicalReplicationMessage::Commit),
        Origin::TAG => Origin::parse_body(&mut payload).map(LogicalReplicationMessage::Origin),
        Relation::TAG => {
            Relation::parse_body(&mut payload).map(LogicalReplicationMessage::Relation)
        }
        Type::TAG => Type::parse_body(&mut payload).map(LogicalReplicationMessage::Type),
        Insert::TAG => Insert::parse_body(&mut payload).map(LogicalReplicationMessage::Insert),
        Update::TAG => Update::parse_body(&mut payload).map(LogicalReplicationMessage::Update),
        Delete::TAG => Delete::parse_body(&mut payload).map(LogicalReplicationMessage::Delete),
        Truncate::TAG => {
            Truncate::parse_body(&mut payload).map(LogicalReplicationMessage::Truncate)
        }
        StreamStart::TAG => {
            StreamStart::parse_body(&mut payload).map(LogicalReplicationMessage::StreamStart)
        }
        StreamStop::TAG => {
            StreamStop::parse_body(&mut payload).map(LogicalReplicationMessage::StreamStop)
        }
        StreamCommit::TAG => {
            StreamCommit::parse_body(&mut payload).map(LogicalReplicationMessage::StreamCommit)
        }
        StreamAbort::TAG => {
            StreamAbort::parse_body(&mut payload).map(LogicalReplicationMessage::StreamAbort)
        }
        other => anyhow::bail!("unsupported pgoutput message tag {:?}", other as char),
    }
}
