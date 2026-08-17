use std::path::Path;

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

use super::client::ControlClient;
use super::client::{control_words, field};
use super::{ControlLine, ProtocolInfo, TorControlError};

const SERVER_HASH_KEY: &[u8] = b"Tor safe cookie authentication server-to-controller hash";
const CLIENT_HASH_KEY: &[u8] = b"Tor safe cookie authentication controller-to-server hash";
const NONCE_LEN: usize = 32;
const COOKIE_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMethod {
    SafeCookie,
    Cookie,
    HashedPassword,
    Null,
    Unknown(String),
}

impl AuthMethod {
    pub(crate) fn parse(value: &str) -> Self {
        match value {
            "SAFECOOKIE" => Self::SafeCookie,
            "COOKIE" => Self::Cookie,
            "HASHEDPASSWORD" => Self::HashedPassword,
            "NULL" => Self::Null,
            value => Self::Unknown(value.to_string()),
        }
    }
}

impl ControlClient {
    pub async fn authenticate(&self, protocol: &ProtocolInfo) -> Result<(), TorControlError> {
        if protocol.auth_methods.contains(&AuthMethod::SafeCookie) {
            let cookie_file = protocol
                .cookie_file
                .as_deref()
                .ok_or(TorControlError::MissingCookieFile)?;
            return self.authenticate_safecookie(cookie_file).await;
        }

        if protocol.auth_methods.contains(&AuthMethod::Cookie) {
            let cookie_file = protocol
                .cookie_file
                .as_deref()
                .ok_or(TorControlError::MissingCookieFile)?;
            return self.authenticate_cookie(cookie_file).await;
        }

        if protocol.auth_methods.contains(&AuthMethod::Null) {
            self.command_success("AUTHENTICATE").await?;
            return Ok(());
        }

        Err(TorControlError::UnsupportedAuthentication(
            protocol.auth_methods.clone(),
        ))
    }

    pub async fn authenticate_safecookie(
        &self,
        cookie_file: impl AsRef<Path>,
    ) -> Result<(), TorControlError> {
        let cookie = read_cookie(cookie_file.as_ref()).await?;
        let mut client_nonce = [0_u8; NONCE_LEN];
        rand::rngs::OsRng.try_fill_bytes(&mut client_nonce)?;

        let challenge = self
            .command_success(format!(
                "AUTHCHALLENGE SAFECOOKIE {}",
                encode_hex(&client_nonce)
            ))
            .await?;
        let (server_hash, server_nonce) = parse_challenge(&challenge.lines)?;
        if !verify_safecookie_hash(
            SERVER_HASH_KEY,
            &cookie,
            &client_nonce,
            &server_nonce,
            &server_hash,
        ) {
            return Err(TorControlError::InvalidServerHash);
        }

        let client_hash = safecookie_hash(CLIENT_HASH_KEY, &cookie, &client_nonce, &server_nonce);
        self.command_success(format!("AUTHENTICATE {}", encode_hex(&client_hash)))
            .await?;
        Ok(())
    }

    async fn authenticate_cookie(&self, cookie_file: &Path) -> Result<(), TorControlError> {
        let cookie = read_cookie(cookie_file).await?;
        self.command_success(format!("AUTHENTICATE {}", encode_hex(&cookie)))
            .await?;
        Ok(())
    }
}

async fn read_cookie(path: &Path) -> Result<[u8; COOKIE_LEN], TorControlError> {
    let bytes = tokio::fs::read(path).await?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| TorControlError::InvalidCookieLength(bytes.len()))
}

fn parse_challenge(lines: &[ControlLine]) -> Result<(Vec<u8>, Vec<u8>), TorControlError> {
    let words = lines
        .iter()
        .find_map(|line| match line {
            ControlLine::Text(value) if value.starts_with("AUTHCHALLENGE ") => {
                Some(control_words(value))
            }
            _ => None,
        })
        .ok_or(TorControlError::MissingChallengeField("AUTHCHALLENGE"))?;

    let server_hash =
        field(&words, "SERVERHASH").ok_or(TorControlError::MissingChallengeField("SERVERHASH"))?;
    let server_nonce = field(&words, "SERVERNONCE")
        .ok_or(TorControlError::MissingChallengeField("SERVERNONCE"))?;
    let server_hash = decode_hex("SERVERHASH", server_hash)?;
    let server_nonce = decode_hex("SERVERNONCE", server_nonce)?;
    if server_hash.len() != 32 {
        return Err(TorControlError::InvalidHex {
            field: "SERVERHASH",
            value: encode_hex(&server_hash),
        });
    }
    if server_nonce.len() != NONCE_LEN {
        return Err(TorControlError::InvalidHex {
            field: "SERVERNONCE",
            value: encode_hex(&server_nonce),
        });
    }
    Ok((server_hash, server_nonce))
}

fn safecookie_hash(
    key: &[u8],
    cookie: &[u8; COOKIE_LEN],
    client_nonce: &[u8; NONCE_LEN],
    server_nonce: &[u8],
) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(cookie);
    mac.update(client_nonce);
    mac.update(server_nonce);
    mac.finalize().into_bytes().into()
}

fn verify_safecookie_hash(
    key: &[u8],
    cookie: &[u8; COOKIE_LEN],
    client_nonce: &[u8; NONCE_LEN],
    server_nonce: &[u8],
    hash: &[u8],
) -> bool {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(cookie);
    mac.update(client_nonce);
    mac.update(server_nonce);
    mac.verify_slice(hash).is_ok()
}

pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn decode_hex(field_name: &'static str, value: &str) -> Result<Vec<u8>, TorControlError> {
    if value.len() % 2 != 0 {
        return Err(TorControlError::InvalidHex {
            field: field_name,
            value: value.to_string(),
        });
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_digit(pair[0]);
            let low = hex_digit(pair[1]);
            match (high, low) {
                (Some(high), Some(low)) => Ok((high << 4) | low),
                _ => Err(TorControlError::InvalidHex {
                    field: field_name,
                    value: value.to_string(),
                }),
            }
        })
        .collect()
}

fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safecookie_hmac_vectors_are_stable() {
        let cookie = [0x11; 32];
        let client_nonce = [0x22; 32];
        let server_nonce = [0x33; 32];

        assert_eq!(
            encode_hex(&safecookie_hash(
                SERVER_HASH_KEY,
                &cookie,
                &client_nonce,
                &server_nonce,
            )),
            "FC0B2C069DB253F5CE08D7867C520D1E2B64F18D81FCF888802A89EC5F097874"
        );
        assert_eq!(
            encode_hex(&safecookie_hash(
                CLIENT_HASH_KEY,
                &cookie,
                &client_nonce,
                &server_nonce,
            )),
            "E20AB915DF5B06CA94B1F465770A1F2D3D3171E5A035F406761B24B74ADB0368"
        );
    }
}
