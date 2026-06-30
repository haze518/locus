use bytes::{BufMut, Bytes, BytesMut};

use crate::core::ConnectParams;

pub(crate) fn encode_startup_message(params: &ConnectParams) -> Bytes {
    let mut buf = BytesMut::new();

    buf.put_u32(0);

    buf.put_u32(196608);

    put_cstr(&mut buf, "user");
    put_cstr(&mut buf, &params.user_name);

    put_cstr(&mut buf, "database");
    put_cstr(&mut buf, &params.database);

    put_cstr(&mut buf, "replication");
    put_cstr(&mut buf, &params.replication_mode); // usually "database"

    buf.put_u8(0);

    let len = buf.len() as u32;
    buf[..4].copy_from_slice(&len.to_be_bytes());

    buf.freeze()
}

fn put_cstr(buf: &mut BytesMut, s: &str) {
    buf.put_slice(s.as_bytes());
    buf.put_u8(0);
}
