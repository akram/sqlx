use crate::connection::stream::PgStream;
use crate::error::Error;
use crate::message::{Authentication, AuthenticationSasl, SaslInitialResponse, SaslResponse};
#[cfg(any(feature = "openssl", feature = "scram-rust-crypto"))]
use crate::rt;
use crate::PgConnectOptions;
#[cfg(all(feature = "scram-rust-crypto", not(feature = "openssl")))]
use hmac::{Hmac, HmacReset, KeyInit, Mac};
#[cfg(all(feature = "scram-rust-crypto", not(feature = "openssl")))]
use sha2::{Digest, Sha256};
use stringprep::saslprep;

use base64::prelude::{Engine as _, BASE64_STANDARD};
use rand::RngExt;

const GS2_HEADER: &str = "n,,";
const CHANNEL_ATTR: &str = "c";
const USERNAME_ATTR: &str = "n";
const CLIENT_PROOF_ATTR: &str = "p";
const NONCE_ATTR: &str = "r";

pub(crate) async fn authenticate(
    stream: &mut PgStream,
    options: &PgConnectOptions,
    data: AuthenticationSasl,
) -> Result<(), Error> {
    let mut has_sasl = false;
    let mut has_sasl_plus = false;
    let mut unknown = Vec::new();

    for mechanism in data.mechanisms() {
        match mechanism {
            "SCRAM-SHA-256" => {
                has_sasl = true;
            }

            "SCRAM-SHA-256-PLUS" => {
                has_sasl_plus = true;
            }

            _ => {
                unknown.push(mechanism.to_owned());
            }
        }
    }

    if !has_sasl_plus && !has_sasl {
        return Err(err_protocol!(
            "unsupported SASL authentication mechanisms: {}",
            unknown.join(", ")
        ));
    }

    // channel-binding = "c=" base64
    let mut channel_binding = format!("{CHANNEL_ATTR}=");
    BASE64_STANDARD.encode_string(GS2_HEADER, &mut channel_binding);

    // "n=" saslname ;; Usernames are prepared using SASLprep.
    let username = format!("{}={}", USERNAME_ATTR, options.username);
    let username = match saslprep(&username) {
        Ok(v) => v,
        Err(error) => {
            return Err(Error::Configuration(
                format!("Failed to saslprep username: {:?}", error).into(),
            ))
        }
    };

    // nonce = "r=" c-nonce [s-nonce] ;; Second part provided by server.
    let nonce = gen_nonce();

    // client-first-message-bare = [reserved-mext ","] username "," nonce ["," extensions]
    let client_first_message_bare = format!("{username},{nonce}");

    let client_first_message = format!("{GS2_HEADER}{client_first_message_bare}");

    stream
        .send(SaslInitialResponse {
            response: &client_first_message,
            plus: false,
        })
        .await?;

    let cont = match stream.recv_expect().await? {
        Authentication::SaslContinue(data) => data,

        auth => {
            return Err(err_protocol!(
                "expected SASLContinue but received {:?}",
                auth
            ));
        }
    };

    // Normalize(password):
    let password = options.password.as_deref().unwrap_or_default();
    let password = match saslprep(password) {
        Ok(v) => v,
        Err(error) => {
            return Err(Error::Configuration(
                format!("Failed to saslprep password: {:?}", error).into(),
            ))
        }
    };

    // SaltedPassword := Hi(Normalize(password), salt, i)
    let salted_password = hi(&password, &cont.salt, cont.iterations).await?;

    // ClientKey := HMAC(SaltedPassword, "Client Key")
    let client_key = hmac_sha256(&salted_password, b"Client Key")?;

    // StoredKey := H(ClientKey)
    let stored_key = sha256_digest(&client_key);

    // client-final-message-without-proof
    let client_final_message_wo_proof = format!(
        "{channel_binding},r={nonce}",
        channel_binding = channel_binding,
        nonce = &cont.nonce
    );

    // AuthMessage := client-first-message-bare + "," + server-first-message + "," + client-final-message-without-proof
    let auth_message = format!(
        "{client_first_message_bare},{server_first_message},{client_final_message_wo_proof}",
        client_first_message_bare = client_first_message_bare,
        server_first_message = cont.message,
        client_final_message_wo_proof = client_final_message_wo_proof
    );

    // ClientSignature := HMAC(StoredKey, AuthMessage)
    let client_signature = hmac_sha256(&stored_key, auth_message.as_bytes())?;

    // ClientProof := ClientKey XOR ClientSignature
    let client_proof: Vec<u8> = client_key
        .iter()
        .zip(client_signature.iter())
        .map(|(&a, &b)| a ^ b)
        .collect();

    // ServerKey := HMAC(SaltedPassword, "Server Key")
    let server_key = hmac_sha256(&salted_password, b"Server Key")?;

    // ServerSignature := HMAC(ServerKey, AuthMessage)
    let server_signature = hmac_sha256(&server_key, auth_message.as_bytes())?;

    // client-final-message = client-final-message-without-proof "," proof
    let mut client_final_message = format!("{client_final_message_wo_proof},{CLIENT_PROOF_ATTR}=");
    BASE64_STANDARD.encode_string(client_proof, &mut client_final_message);

    stream.send(SaslResponse(&client_final_message)).await?;

    let data = match stream.recv_expect().await? {
        Authentication::SaslFinal(data) => data,

        auth => {
            return Err(err_protocol!("expected SASLFinal but received {:?}", auth));
        }
    };

    // authentication is only considered valid if this verification passes
    if !constant_time_eq(&server_signature, &data.verifier) {
        return Err(Error::protocol("SCRAM server signature verification failed"));
    }

    Ok(())
}

// nonce is a sequence of random printable bytes
fn gen_nonce() -> String {
    let mut rng = rand::rng();
    let count = rng.random_range(64..128);

    // printable = %x21-2B / %x2D-7E
    // ;; Printable ASCII except ",".
    // ;; Note that any "printable" is also
    // ;; a valid "value".
    let nonce: String = std::iter::repeat(())
        .map(|()| {
            let mut c = rng.random_range(0x21u8..0x7F);

            while c == 0x2C {
                c = rng.random_range(0x21u8..0x7F);
            }

            c
        })
        .take(count)
        .map(|c| c as char)
        .collect();

    format!("{NONCE_ATTR}={nonce}")
}

/// HMAC-SHA256(key, data), one-shot.
#[cfg(feature = "openssl")]
fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; 32], Error> {
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::sign::Signer;

    let pkey = PKey::hmac(key).map_err(Error::protocol)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey).map_err(Error::protocol)?;
    let sig = signer.sign_oneshot_to_vec(data).map_err(Error::protocol)?;

    sig.try_into()
        .map_err(|_| err_protocol!("hmac-sha256 output was not 32 bytes"))
}

#[cfg(all(feature = "scram-rust-crypto", not(feature = "openssl")))]
fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; 32], Error> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(Error::protocol)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().into())
}

#[cfg(not(any(feature = "openssl", feature = "scram-rust-crypto")))]
fn hmac_sha256(_key: &[u8], _data: &[u8]) -> Result<[u8; 32], Error> {
    Err(Error::Configuration(
        "postgres SCRAM-SHA-256 authentication requires the `openssl` or `scram-rust-crypto` feature".into(),
    ))
}

/// SHA-256(data), one-shot.
#[cfg(feature = "openssl")]
fn sha256_digest(data: &[u8]) -> [u8; 32] {
    let digest = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), data)
        .expect("sha256 is infallible with a correctly installed OpenSSL backend");
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(all(feature = "scram-rust-crypto", not(feature = "openssl")))]
fn sha256_digest(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

#[cfg(not(any(feature = "openssl", feature = "scram-rust-crypto")))]
fn sha256_digest(_data: &[u8]) -> [u8; 32] {
    unreachable!("unreachable without a SCRAM backend: `hi()` already returns `Err` first")
}

/// Constant-time comparison, for verifying the server's SCRAM signature.
#[cfg(feature = "openssl")]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && openssl::memcmp::eq(a, b)
}

#[cfg(all(feature = "scram-rust-crypto", not(feature = "openssl")))]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

#[cfg(not(any(feature = "openssl", feature = "scram-rust-crypto")))]
fn constant_time_eq(_a: &[u8], _b: &[u8]) -> bool {
    unreachable!("unreachable without a SCRAM backend: `hi()` already returns `Err` first")
}

// Hi(str, salt, i):
//
// This is PBKDF2-HMAC-SHA256(str, salt, i, dkLen=32) (RFC 8018 5.2's `F`, for block index 1,
// since the derived key length equals the digest size, i.e. a single block): `U(1) = HMAC(str,
// salt || INT(1))`, `U(c) = HMAC(str, U(c-1))`, result = `U(1) XOR U(2) XOR ... XOR U(iter_count)`.
#[cfg(feature = "openssl")]
async fn hi(s: &str, salt: &[u8], iter_count: u32) -> Result<[u8; 32], Error> {
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::sign::Signer;

    // The loop below yields periodically (same as the RustCrypto version) rather than using
    // `openssl::pkcs5::pbkdf2_hmac` directly, which would otherwise block the executor for the
    // whole computation (measured at ~50ms for 4096 iterations, the default, on a developer
    // machine) with no yield points.
    let key = PKey::hmac(s.as_bytes()).map_err(Error::protocol)?;
    let sign = |data: &[u8]| -> Result<[u8; 32], Error> {
        let mut signer = Signer::new(MessageDigest::sha256(), &key).map_err(Error::protocol)?;
        let sig = signer.sign_oneshot_to_vec(data).map_err(Error::protocol)?;
        sig.try_into()
            .map_err(|_| err_protocol!("hmac-sha256 output was not 32 bytes"))
    };

    let mut salt_block = Vec::with_capacity(salt.len() + 4);
    salt_block.extend_from_slice(salt);
    salt_block.extend_from_slice(&1u32.to_be_bytes());

    let mut u = sign(&salt_block)?;
    let mut hi = u;

    for i in 1..iter_count {
        u = sign(&u)?;

        for (h, b) in hi.iter_mut().zip(u.iter()) {
            *h ^= b;
        }

        if i % 5 == 0 {
            rt::yield_now().await;
        }
    }

    Ok(hi)
}

#[cfg(all(feature = "scram-rust-crypto", not(feature = "openssl")))]
async fn hi(s: &str, salt: &[u8], iter_count: u32) -> Result<[u8; 32], Error> {
    let mut mac = HmacReset::<Sha256>::new_from_slice(s.as_bytes()).map_err(Error::protocol)?;

    mac.update(salt);
    mac.update(&1u32.to_be_bytes());

    let mut u = mac.finalize_reset().into_bytes();
    let mut hi = u;

    for i in 1..iter_count {
        mac.update(u.as_slice());
        u = mac.finalize_reset().into_bytes();
        hi = hi.iter().zip(u.iter()).map(|(&a, &b)| a ^ b).collect();

        // For large iteration counts, this process can take a long time and block the event loop.
        // It was measured as taking ~50ms for 4096 iterations (the default) on a developer machine.
        // If we want to yield every 10-100us (as generally advised for tokio), then we can yield
        // every 5 iterations which should be every ~50us.
        if i % 5 == 0 {
            rt::yield_now().await;
        }
    }

    Ok(hi.into())
}

/// Neither backend feature is active. This compiles so the crate still
/// builds in contexts where no consumer forwards a backend choice (e.g.
/// Cargo's host-only feature-unification bucket for a proc-macro crate's
/// own dependency, such as sqlx-macros-core's `sqlx-postgres` -- compiled
/// only to generate code at macro-expansion time, never linked into a
/// shipped binary, so this arm is unreachable in practice for a consumer
/// that, like `sqlx` itself here, forwards one of the two features for
/// its real target build).
#[cfg(not(any(feature = "openssl", feature = "scram-rust-crypto")))]
async fn hi(_s: &str, _salt: &[u8], _iter_count: u32) -> Result<[u8; 32], Error> {
    Err(Error::Configuration(
        "postgres SCRAM-SHA-256 authentication requires the `openssl` or `scram-rust-crypto` feature".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Independent reference implementation of `hi()`'s PBKDF2-HMAC-SHA256,
    // written directly against RustCrypto rather than calling this module's
    // own `hi()` (whichever backend that resolves to), so a bug shared
    // between the two wouldn't go unnoticed.
    fn reference_hi(s: &str, salt: &[u8], iter_count: u32) -> [u8; 32] {
        use ::hmac::{Hmac, KeyInit, Mac};
        use ::sha2::Sha256;

        let mut mac = Hmac::<Sha256>::new_from_slice(s.as_bytes()).unwrap();
        mac.update(salt);
        mac.update(&1u32.to_be_bytes());
        let mut u: [u8; 32] = mac.finalize().into_bytes().into();
        let mut hi = u;

        for _ in 1..iter_count {
            let mut mac = Hmac::<Sha256>::new_from_slice(s.as_bytes()).unwrap();
            mac.update(&u);
            u = mac.finalize().into_bytes().into();
            for (h, b) in hi.iter_mut().zip(u.iter()) {
                *h ^= b;
            }
        }

        hi
    }

    #[test]
    fn hi_matches_reference_implementation() {
        futures_executor::block_on(async {
            for iterations in [1, 2, 5, 11, 4096] {
                let got = hi("correct-password", b"some-random-salt", iterations)
                    .await
                    .unwrap();
                let want = reference_hi("correct-password", b"some-random-salt", iterations);
                assert_eq!(got, want, "mismatch at {iterations} iterations");
            }
        });
    }

    #[test]
    fn hmac_sha256_matches_reference() {
        use ::hmac::{Hmac, KeyInit, Mac};
        use ::sha2::Sha256;

        let got = hmac_sha256(b"Client Key", b"some auth message").unwrap();
        let mut mac = Hmac::<Sha256>::new_from_slice(b"Client Key").unwrap();
        mac.update(b"some auth message");
        let want: [u8; 32] = mac.finalize().into_bytes().into();
        assert_eq!(got, want);
    }

    #[test]
    fn sha256_digest_matches_reference() {
        use ::sha2::{Digest, Sha256};

        let got = sha256_digest(b"some client key");
        let want: [u8; 32] = Sha256::digest(b"some client key").into();
        assert_eq!(got, want);
    }

    #[test]
    fn constant_time_eq_self_consistent() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
