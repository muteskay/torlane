use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;

use rand::RngCore;
use rand::rngs::OsRng;

use crate::pool::SocksAuth;
use crate::tor::error::TorIdentityError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorIdentity {
    pub id: u64,
    pub proxy_addr: SocketAddr,
    pub auth: SocksAuth,
}

/// Runtime-only SOCKS identities for Tor stream isolation.
///
/// Different SOCKS username/password pairs cause Tor to isolate streams and
/// circuits when `IsolateSOCKSAuth` is enabled. This does not guarantee a
/// unique exit relay IP for each identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorIdentityPool {
    identities: Vec<TorIdentity>,
}

impl TorIdentityPool {
    pub fn generate(proxy_addr: SocketAddr, count: usize) -> Result<Self, TorIdentityError> {
        if count == 0 {
            return Err(TorIdentityError::EmptyIdentityPool);
        }

        let mut identities = Vec::with_capacity(count);
        let mut passwords = HashSet::with_capacity(count);

        for id in 0..count {
            let username = format!("worker-{id:06}");
            let mut password = random_hex(32)?;
            while !passwords.insert(password.clone()) {
                password = random_hex(32)?;
            }

            identities.push(TorIdentity {
                id: id as u64,
                proxy_addr,
                auth: SocksAuth {
                    username: Arc::from(username),
                    password: Arc::from(password),
                },
            });
        }

        Ok(Self { identities })
    }

    pub fn identity_count(&self) -> usize {
        self.identities.len()
    }

    pub fn isolated_identity(&self, index: usize) -> Option<&TorIdentity> {
        self.identities.get(index)
    }

    pub fn get(&self, index: usize) -> Option<&TorIdentity> {
        self.isolated_identity(index)
    }

    pub fn identities(&self) -> &[TorIdentity] {
        &self.identities
    }
}

fn random_hex(bytes: usize) -> Result<String, TorIdentityError> {
    let mut random = vec![0_u8; bytes];
    secure_random(&mut random)?;
    Ok(hex_encode(&random))
}

fn secure_random(bytes: &mut [u8]) -> Result<(), TorIdentityError> {
    OsRng.try_fill_bytes(bytes)?;
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
