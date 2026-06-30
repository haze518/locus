use bytes::{BufMut, Bytes, BytesMut};

use crate::core::ConnectParams;

pub(crate) trait Codec: Sized {
    fn decode(buf: Bytes) -> anyhow::Result<Self>;
    fn encode(&self) -> anyhow::Result<Bytes>;
}

pub(crate) struct StartupMessage {
    pub(crate) user_name: String,
    pub(crate) database: String,
    pub(crate) replication: String,
}

impl Codec for StartupMessage {
    fn decode(buf: Bytes) -> anyhow::Result<Self> {
        todo!()
    }
    fn encode(&self) -> anyhow::Result<Bytes> {
        let mut buf = BytesMut::new();

        buf.put_u32(0);

        buf.put_u32(196608);

        put_cstr(&mut buf, "user");
        put_cstr(&mut buf, &self.user_name);

        put_cstr(&mut buf, "database");
        put_cstr(&mut buf, &self.database);

        put_cstr(&mut buf, "replication");
        put_cstr(&mut buf, &self.replication); // usually "database"

        buf.put_u8(0);

        let len = buf.len() as u32;
        buf[..4].copy_from_slice(&len.to_be_bytes());

        Ok(buf.freeze())
    }
}

pub(crate) struct SASLInitialResponse {
    auth_mechanism: String,
    data: Bytes,
    // TODO add generate data
}

impl Codec for SASLInitialResponse {
    fn decode(buf: Bytes) -> anyhow::Result<Self> {
        todo!()
    }
    fn encode(&self) -> anyhow::Result<Bytes> {
        let mut buf = BytesMut::new();

        buf.put_u8(b'p');

        buf.put_u32(0);

        put_cstr(&mut buf, &self.auth_mechanism);

        buf.put_i32(self.data.len() as i32);
        buf.put_slice(&self.data);

        let len = (buf.len() - 1) as u32;
        buf[1..5].copy_from_slice(&len.to_be_bytes());

        Ok(buf.freeze())
    }
}

fn put_cstr(buf: &mut BytesMut, s: &str) {
    buf.put_slice(s.as_bytes());
    buf.put_u8(0);
}
