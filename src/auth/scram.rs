use anyhow::Context;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use bytes::{BufMut, Bytes, BytesMut};
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use rand::TryRng;
use rand::rngs::SysRng;
use sha2::{Digest, Sha256};

use crate::protocol;

pub(crate) const SCRAM_SHA_256_NAME: &str = "SCRAM-SHA-256";
pub(crate) const CLIENT_NONCE_LEN: usize = 18;
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug)]
pub(crate) struct ScramClient {
    server_mechanisms: Vec<String>,
    mechanism: String,
    client_nonce: String,
    password: String,
    server_first_message: Option<Bytes>,
    client_and_server_nonce: Option<Bytes>,
    salt: Option<Bytes>,
    iterations: Option<u32>,
}

impl ScramClient {
    pub(crate) fn new(
        server_mechanisms: Vec<String>,
        password: String,
    ) -> anyhow::Result<ScramClient> {
        if !server_mechanisms.iter().any(|m| m == SCRAM_SHA_256_NAME) {
            anyhow::bail!("server doesn't support SCRAM-SHA-256");
        }

        let mut nonce_bytes = [0u8; CLIENT_NONCE_LEN];
        SysRng
            .try_fill_bytes(&mut nonce_bytes)
            .context("generate SCRAM client nonce")?;

        let client_nonce = STANDARD_NO_PAD.encode(nonce_bytes);

        Ok(ScramClient {
            server_mechanisms,
            mechanism: SCRAM_SHA_256_NAME.to_string(),
            client_nonce,
            password,
            server_first_message: None,
            client_and_server_nonce: None,
            salt: None,
            iterations: None,
        })
    }

    pub(crate) fn initial_response(&self) -> protocol::SASLInitialResponse {
        protocol::SASLInitialResponse {
            auth_mechanism: self.mechanism.clone(),
            data: self.client_first_message(),
        }
    }

    pub(crate) fn final_response(&self) -> anyhow::Result<protocol::SASLResponse> {
        Ok(protocol::SASLResponse {
            data: self.client_final_message()?,
        })
    }

    pub(crate) fn handle_server_first(&mut self, data: Bytes) -> anyhow::Result<()> {
        self.server_first_message = Some(data.clone());

        let mut buf = data.as_ref();

        buf = buf
            .strip_prefix(b"r=")
            .ok_or_else(|| anyhow::anyhow!("invalid SCRAM server-first-message: missing r="))?;

        let idx = buf
            .iter()
            .position(|&b| b == b',')
            .ok_or_else(|| anyhow::anyhow!("invalid SCRAM server-first-message: missing s="))?;

        let client_and_server_nonce = Bytes::copy_from_slice(&buf[..idx]);
        buf = &buf[idx + 1..];

        buf = buf
            .strip_prefix(b"s=")
            .ok_or_else(|| anyhow::anyhow!("invalid SCRAM server-first-message: missing s="))?;

        let idx = buf
            .iter()
            .position(|&b| b == b',')
            .ok_or_else(|| anyhow::anyhow!("invalid SCRAM server-first-message: missing i="))?;

        let salt = &buf[..idx];
        buf = &buf[idx + 1..];

        buf = buf
            .strip_prefix(b"i=")
            .ok_or_else(|| anyhow::anyhow!("invalid SCRAM server-first-message: missing i="))?;

        let salt_decoded = STANDARD
            .decode(salt)
            .context("invalid SCRAM salt received from server")?;

        let iterations = std::str::from_utf8(buf)?
            .parse::<u32>()
            .context("invalid SCRAM iteration count received from server")?;

        if iterations == 0 {
            anyhow::bail!("invalid SCRAM iteration count");
        }

        if !client_and_server_nonce.starts_with(self.client_nonce.as_bytes()) {
            anyhow::bail!("invalid SCRAM nonce: did not start with client nonce");
        }

        if client_and_server_nonce.len() <= self.client_nonce.len() {
            anyhow::bail!("invalid SCRAM nonce: did not include server nonce");
        }

        self.client_and_server_nonce = Some(client_and_server_nonce);
        self.salt = Some(Bytes::from(salt_decoded));
        self.iterations = Some(iterations);

        Ok(())
    }

    pub(crate) fn handle_server_final(&mut self, data: Bytes) -> anyhow::Result<()> {
        let server_signature = data
            .as_ref()
            .strip_prefix(b"v=")
            .ok_or_else(|| anyhow::anyhow!("invalid SCRAM server-final-message"))?;

        let salted_password = self.salted_password()?;
        let auth_message = self.auth_message()?;

        let server_key = hmac_sha256(&salted_password, b"Server Key")?;
        let signature = hmac_sha256(&server_key, &auth_message)?;

        let expected_signature = STANDARD.encode(signature).into_bytes();

        if server_signature != expected_signature.as_slice() {
            anyhow::bail!("invalid SCRAM server signature");
        }

        Ok(())
    }

    fn client_first_message(&self) -> Bytes {
        let mut result = BytesMut::new();

        result.put_slice(&self.client_gs2_header());
        result.put_slice(&self.client_first_message_bare());

        result.freeze()
    }

    fn client_final_message(&self) -> anyhow::Result<Bytes> {
        let salted_password = self.salted_password()?;
        let auth_message = self.auth_message()?;

        let client_key = hmac_sha256(&salted_password, b"Client Key")?;
        let stored_key = Sha256::digest(&client_key);
        let client_signature = hmac_sha256(&stored_key, &auth_message)?;

        let client_proof: Vec<u8> = client_key
            .iter()
            .zip(client_signature.iter())
            .map(|(a, b)| a ^ b)
            .collect();

        let client_proof_encoded = STANDARD.encode(client_proof);
        let client_message_without_proof = self.client_message_without_proof()?;

        let mut result = BytesMut::new();

        result.put_slice(&client_message_without_proof);
        result.put_slice(b",p=");
        result.put_slice(client_proof_encoded.as_bytes());

        Ok(result.freeze())
    }

    fn client_first_message_bare(&self) -> Bytes {
        let mut buf = BytesMut::new();

        buf.put_slice(b"n=,r=");
        buf.put_slice(self.client_nonce.as_bytes());

        buf.freeze()
    }

    fn client_gs2_header(&self) -> Bytes {
        Bytes::from_static(b"n,,")
    }

    fn salted_password(&self) -> anyhow::Result<[u8; 32]> {
        let salt = self
            .salt
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing salt"))?;

        let iterations = self
            .iterations
            .ok_or_else(|| anyhow::anyhow!("missing iterations"))?;

        let mut out = [0u8; 32];

        pbkdf2_hmac::<Sha256>(self.password.as_bytes(), salt, iterations, &mut out);

        Ok(out)
    }

    fn auth_message(&self) -> anyhow::Result<Bytes> {
        let server_first_message = self
            .server_first_message
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing server first message"))?;

        let client_message_without_proof = self.client_message_without_proof()?;

        let mut result = BytesMut::new();

        result.put_slice(&self.client_first_message_bare());
        result.put_u8(b',');
        result.put_slice(server_first_message);
        result.put_u8(b',');
        result.put_slice(&client_message_without_proof);

        Ok(result.freeze())
    }

    fn client_message_without_proof(&self) -> anyhow::Result<Bytes> {
        let nonce = self
            .client_and_server_nonce
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing client_and_server_nonce"))?;

        let mut result = BytesMut::new();

        result.put_slice(b"c=biws");
        result.put_slice(b",r=");
        result.put_slice(nonce);

        Ok(result.freeze())
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(key).context("create HMAC-SHA256")?;

    mac.update(data);

    Ok(mac.finalize().into_bytes().to_vec())
}
