// NTLMv2 authentication (MS-NLMP).
//
// Exists for one reason: signing needs a session key, and only a real
// authentication produces one. There is no guest path to fall back to — every
// client on every platform runs through here.
//
// Everything here is MD4, MD5 and RC4 — all broken primitives. They are not a
// security choice; they are what NTLMv2 is specified in terms of, and a client
// will not interoperate with anything else. The security of this share comes
// from the password and from being on a trusted network, not from these.
//
// Deliberately not implemented: the AUTHENTICATE **MIC**. A client that sets
// MsvAvFlags bit 0x02 in its NTLMv2 blob has included an HMAC-MD5 over the
// three-message exchange, and a full server checks it (Samba:
// `auth/ntlmssp/ntlmssp_server.c:570-597` and `:1088-1158`) — that check is
// what CVE-2019-1040 was about. It is omitted here because the attack it stops
// is NTLM *relay*: tampering with the negotiate flags of an exchange being
// forwarded to a third party. This server is the only party, authenticates a
// single fixed local account, ignores the client's negotiate flags entirely
// (so there is nothing in them to downgrade), and mandates signing on every
// message after the handshake. Implementing it would mean retaining the raw
// NEGOTIATE and CHALLENGE blobs per connection and parsing the AV-pair list,
// for a guarantee nothing here rests on. If this ever grows a second account,
// a non-loopback default, or any form of pass-through authentication, that
// reasoning expires and the MIC becomes mandatory.

use hmac::{Hmac, Mac};
use md4::Md4;
use md5::Md5;
// `Rc4::new` is typed to a 32-byte key; NTLM's is 16, so the slice constructor
// is the one to use — it accepts any length the cipher allows.
use rc4::{KeyInit as Rc4KeyInit, Rc4, StreamCipher};
use subtle::ConstantTimeEq;

use super::wire::utf16le;

type HmacMd5 = Hmac<Md5>;

/// NTLMSSP negotiate flags we care about (MS-NLMP 2.2.2.5).
pub(crate) mod flags {
    pub(crate) const NEGOTIATE_UNICODE: u32 = 0x0000_0001;
    pub(crate) const REQUEST_TARGET: u32 = 0x0000_0004;
    pub(crate) const NEGOTIATE_SIGN: u32 = 0x0000_0010;
    pub(crate) const NEGOTIATE_NTLM: u32 = 0x0000_0200;
    pub(crate) const NEGOTIATE_ANONYMOUS: u32 = 0x0000_0800;
    pub(crate) const NEGOTIATE_ALWAYS_SIGN: u32 = 0x0000_8000;
    pub(crate) const TARGET_TYPE_SERVER: u32 = 0x0002_0000;
    pub(crate) const EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
    pub(crate) const NEGOTIATE_TARGET_INFO: u32 = 0x0080_0000;
    pub(crate) const NEGOTIATE_KEY_EXCH: u32 = 0x4000_0000;
    pub(crate) const NEGOTIATE_128: u32 = 0x2000_0000;
    pub(crate) const NEGOTIATE_56: u32 = 0x8000_0000;
}

/// NTOWFv1: the NT hash, MD4 over the UTF-16LE password.
fn nt_hash(password: &str) -> [u8; 16] {
    use md4::Digest;
    let mut h = Md4::new();
    h.update(utf16le(password));
    h.finalize().into()
}

/// NTOWFv2 = HMAC-MD5(NT hash, uppercase(user) || domain), both UTF-16LE.
///
/// The username is upper-cased but the domain is not — an asymmetry in the spec
/// that is easy to "fix" into a bug, because getting it wrong yields a proof
/// string that never matches and an authentication that always fails.
///
/// `to_uppercase` is Rust's full Unicode mapping, where Windows uses the
/// invariant table — they disagree on characters like ß (which Rust expands to
/// SS). The CLI restricts account names to ASCII, and this is noted
/// here because it stops being irrelevant the moment the user name is not.
fn ntowf_v2(password: &str, user: &str, domain: &str) -> [u8; 16] {
    let mut mac = HmacMd5::new_from_slice(&nt_hash(password)).expect("HMAC takes any key length");
    mac.update(&utf16le(&user.to_uppercase()));
    mac.update(&utf16le(domain));
    mac.finalize().into_bytes().into()
}

fn hmac_md5(key: &[u8], data: &[&[u8]]) -> [u8; 16] {
    let mut mac = HmacMd5::new_from_slice(key).expect("HMAC takes any key length");
    for part in data {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// A field descriptor in an NTLM message: (len, max_len, offset).
fn field(buf: &[u8], at: usize) -> Option<(usize, usize)> {
    if buf.len() < at + 8 {
        return None;
    }
    let len = u16::from_le_bytes(buf[at..at + 2].try_into().ok()?) as usize;
    let off = u32::from_le_bytes(buf[at + 4..at + 8].try_into().ok()?) as usize;
    Some((off, len))
}

fn slice(buf: &[u8], at: usize) -> Option<&[u8]> {
    let (off, len) = field(buf, at)?;
    if len == 0 {
        return Some(&[]);
    }
    buf.get(off..off.checked_add(len)?)
}

fn utf16_string(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    String::from_utf16_lossy(&units)
}

/// The parts of an NTLMSSP AUTHENTICATE message this server uses
/// (MS-NLMP 2.2.1.3).
#[derive(Debug)]
pub(crate) struct Authenticate {
    pub(crate) user: String,
    pub(crate) domain: String,
    /// NTProofStr (16 bytes) followed by the blob it was computed over.
    nt_response: Vec<u8>,
    encrypted_session_key: Vec<u8>,
    pub(crate) flags: u32,
}

impl Authenticate {
    pub(crate) fn parse(msg: &[u8]) -> Option<Self> {
        // 0 Signature[8], 8 MessageType, 12 LmChallengeResponseFields,
        // 20 NtChallengeResponseFields, 28 DomainNameFields, 36 UserNameFields,
        // 44 WorkstationFields, 52 EncryptedRandomSessionKeyFields, 60 Flags.
        if msg.len() < 64 {
            return None;
        }
        let nt_response = slice(msg, 20)?.to_vec();
        let domain = utf16_string(slice(msg, 28)?);
        let user = utf16_string(slice(msg, 36)?);
        let encrypted_session_key = slice(msg, 52)?.to_vec();
        let flags = u32::from_le_bytes(msg[60..64].try_into().ok()?);

        Some(Self {
            user,
            domain,
            nt_response,
            encrypted_session_key,
            flags,
        })
    }

    /// True when the client is asking for an anonymous session rather than
    /// presenting credentials. Linux with `sec=none` does this.
    pub(crate) fn is_anonymous(&self) -> bool {
        self.flags & flags::NEGOTIATE_ANONYMOUS != 0
            || (self.user.is_empty() && self.nt_response.len() <= 24)
    }
}

/// Verify an AUTHENTICATE against `password` and return the session key that
/// signing will use.
///
/// Returns `None` on any mismatch. The comparison of the proof string is
/// constant-time: it is a MAC check, and a timing oracle on it would let an
/// attacker forge one byte at a time.
pub(crate) fn verify(
    auth: &Authenticate,
    password: &str,
    server_challenge: &[u8; 8],
) -> Option<[u8; 16]> {
    // NtChallengeResponse is NTProofStr(16) || temp. Anything shorter is either
    // an LMv2-only response or a malformed message; neither can be verified.
    if auth.nt_response.len() < 16 {
        return None;
    }
    let (proof, temp) = auth.nt_response.split_at(16);

    let key = ntowf_v2(password, &auth.user, &auth.domain);
    let expected = hmac_md5(&key, &[server_challenge.as_slice(), temp]);

    if proof.ct_eq(&expected[..]).unwrap_u8() == 0 {
        return None;
    }

    let session_base_key = hmac_md5(&key, &[&expected]);

    // With key exchange the client generates the real session key, encrypts it
    // under the base key with RC4, and we recover it. Without it, the base key
    // is the session key.
    if auth.flags & flags::NEGOTIATE_KEY_EXCH == 0 {
        return Some(session_base_key);
    }
    // KEY_EXCH negotiated, so the exported key *is* the decrypted field —
    // MS-NLMP 3.1.5.1.2 defines no fallback. Falling back to the base key
    // anyway would let a non-conforming client "authenticate" and then have
    // every subsequent message fail its signature, which is the least
    // diagnosable outcome available. Samba refuses it outright
    // (`ntlmssp_server.c:1038-1043`, "session key was of invalid length").
    let mut buf: [u8; 16] = auth.encrypted_session_key.as_slice().try_into().ok()?;
    let mut cipher = Rc4::new_from_slice(&session_base_key).expect("16-byte RC4 key is in range");
    cipher.apply_keystream(&mut buf);
    Some(buf)
}

#[cfg(test)]
pub(crate) mod tests_support {
    //! Client-side message construction, shared with the session tests so the
    //! authenticated handshake can be driven end to end.
    use super::*;

    /// Build an AUTHENTICATE message the way a client would, so verification can
    /// be tested against a response we know is correct.
    pub(crate) fn build_authenticate(
        user: &str,
        domain: &str,
        password: &str,
        server_challenge: &[u8; 8],
        key_exchange: Option<[u8; 16]>,
    ) -> Vec<u8> {
        // temp = blob the client invents; its contents do not matter to the
        // server beyond being echoed into the MAC.
        let temp: Vec<u8> = (0..32u8).collect();
        let key = ntowf_v2(password, user, domain);
        let proof = hmac_md5(&key, &[server_challenge.as_slice(), &temp]);

        let mut nt_response = proof.to_vec();
        nt_response.extend_from_slice(&temp);

        let session_base_key = hmac_md5(&key, &[&proof]);
        let (enc_key, flags) = match key_exchange {
            Some(session_key) => {
                let mut buf = session_key;
                let mut cipher =
                    Rc4::new_from_slice(&session_base_key).expect("16-byte RC4 key is in range");
                cipher.apply_keystream(&mut buf);
                (buf.to_vec(), flags::NEGOTIATE_KEY_EXCH)
            }
            None => (Vec::new(), 0),
        };

        let domain_b = utf16le(domain);
        let user_b = utf16le(user);

        let fixed = 64usize;
        let domain_off = fixed;
        let user_off = domain_off + domain_b.len();
        let nt_off = user_off + user_b.len();
        let key_off = nt_off + nt_response.len();

        let mut m = Vec::new();
        m.extend_from_slice(b"NTLMSSP\0");
        m.extend_from_slice(&3u32.to_le_bytes()); // MessageType = AUTHENTICATE
        // LmChallengeResponseFields (unused)
        m.extend_from_slice(&0u16.to_le_bytes());
        m.extend_from_slice(&0u16.to_le_bytes());
        m.extend_from_slice(&0u32.to_le_bytes());
        // NtChallengeResponseFields
        m.extend_from_slice(&(nt_response.len() as u16).to_le_bytes());
        m.extend_from_slice(&(nt_response.len() as u16).to_le_bytes());
        m.extend_from_slice(&(nt_off as u32).to_le_bytes());
        // DomainNameFields
        m.extend_from_slice(&(domain_b.len() as u16).to_le_bytes());
        m.extend_from_slice(&(domain_b.len() as u16).to_le_bytes());
        m.extend_from_slice(&(domain_off as u32).to_le_bytes());
        // UserNameFields
        m.extend_from_slice(&(user_b.len() as u16).to_le_bytes());
        m.extend_from_slice(&(user_b.len() as u16).to_le_bytes());
        m.extend_from_slice(&(user_off as u32).to_le_bytes());
        // WorkstationFields (unused)
        m.extend_from_slice(&0u16.to_le_bytes());
        m.extend_from_slice(&0u16.to_le_bytes());
        m.extend_from_slice(&0u32.to_le_bytes());
        // EncryptedRandomSessionKeyFields
        m.extend_from_slice(&(enc_key.len() as u16).to_le_bytes());
        m.extend_from_slice(&(enc_key.len() as u16).to_le_bytes());
        m.extend_from_slice(&(key_off as u32).to_le_bytes());
        // Flags
        m.extend_from_slice(&flags.to_le_bytes());

        assert_eq!(m.len(), fixed);
        m.extend_from_slice(&domain_b);
        m.extend_from_slice(&user_b);
        m.extend_from_slice(&nt_response);
        m.extend_from_slice(&enc_key);
        m
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::build_authenticate;
    use super::*;

    #[test]
    fn nt_hash_matches_the_known_vector() {
        // MS-NLMP 4.2.2.1.1: password "Password" hashes to this NT hash.
        assert_eq!(
            nt_hash("Password"),
            [
                0xa4, 0xf4, 0x9c, 0x40, 0x65, 0x10, 0xbd, 0xca, 0xb6, 0x82, 0x4e, 0xe7, 0xc3, 0x0f,
                0xd8, 0x52
            ]
        );
    }

    #[test]
    fn ntowf_v2_matches_the_known_vector() {
        // MS-NLMP 4.2.4.1.1: user "User", domain "Domain", password "Password".
        assert_eq!(
            ntowf_v2("Password", "User", "Domain"),
            [
                0x0c, 0x86, 0x8a, 0x40, 0x3b, 0xfd, 0x7a, 0x93, 0xa3, 0x00, 0x1e, 0xf2, 0x2e, 0xf0,
                0x2e, 0x3f
            ]
        );
    }

    #[test]
    fn the_username_is_upper_cased_but_the_domain_is_not() {
        // Same vector as above reached through a lowercase user name.
        assert_eq!(
            ntowf_v2("Password", "user", "Domain"),
            ntowf_v2("Password", "USER", "Domain")
        );
        // The domain is case-sensitive; if it were upper-cased too, these would
        // collide and every mixed-case-domain login would silently still work.
        assert_ne!(
            ntowf_v2("Password", "User", "Domain"),
            ntowf_v2("Password", "User", "DOMAIN")
        );
    }

    #[test]
    fn a_correct_response_verifies_and_yields_a_session_key() {
        let challenge = [0x01u8, 2, 3, 4, 5, 6, 7, 8];
        let msg = build_authenticate("wrustic", "", "hunter2", &challenge, None);
        let auth = Authenticate::parse(&msg).expect("parses");
        assert_eq!(auth.user, "wrustic");
        assert!(!auth.is_anonymous());

        let key = verify(&auth, "hunter2", &challenge).expect("must verify");
        assert_ne!(key, [0u8; 16], "a session key is derived");
    }

    #[test]
    fn a_wrong_password_is_rejected() {
        let challenge = [9u8; 8];
        let msg = build_authenticate("wrustic", "", "hunter2", &challenge, None);
        let auth = Authenticate::parse(&msg).unwrap();
        assert!(verify(&auth, "wrong", &challenge).is_none());
    }

    #[test]
    fn a_response_to_a_different_challenge_is_rejected() {
        // Replaying a capture against a fresh challenge must fail; this is the
        // only thing making the exchange more than a password echo.
        let msg = build_authenticate("wrustic", "", "hunter2", &[1u8; 8], None);
        let auth = Authenticate::parse(&msg).unwrap();
        assert!(verify(&auth, "hunter2", &[2u8; 8]).is_none());
    }

    #[test]
    fn a_tampered_proof_string_is_rejected() {
        let challenge = [3u8; 8];
        let mut msg = build_authenticate("wrustic", "", "hunter2", &challenge, None);
        let auth = Authenticate::parse(&msg).unwrap();
        let good = verify(&auth, "hunter2", &challenge);
        assert!(good.is_some());

        // Flip a bit inside the NT response and re-verify.
        let (off, _) = field(&msg, 20).unwrap();
        msg[off] ^= 0x01;
        let auth = Authenticate::parse(&msg).unwrap();
        assert!(verify(&auth, "hunter2", &challenge).is_none());
    }

    #[test]
    fn key_exchange_recovers_the_clients_session_key() {
        let challenge = [7u8; 8];
        let session_key = [0xAB; 16];
        let msg = build_authenticate("wrustic", "", "hunter2", &challenge, Some(session_key));
        let auth = Authenticate::parse(&msg).unwrap();
        assert_ne!(auth.flags & flags::NEGOTIATE_KEY_EXCH, 0);

        let recovered = verify(&auth, "hunter2", &challenge).expect("verifies");
        assert_eq!(
            recovered, session_key,
            "the server must end up with the key the client chose"
        );
    }

    #[test]
    fn an_anonymous_authenticate_is_recognised() {
        let mut msg = build_authenticate("", "", "", &[0u8; 8], None);
        // Set the anonymous flag the way a client requesting a null session does.
        let flags_at = 60;
        let f = u32::from_le_bytes(msg[flags_at..flags_at + 4].try_into().unwrap());
        msg[flags_at..flags_at + 4]
            .copy_from_slice(&(f | flags::NEGOTIATE_ANONYMOUS).to_le_bytes());

        let auth = Authenticate::parse(&msg).unwrap();
        assert!(auth.is_anonymous());
    }

    #[test]
    fn a_truncated_message_is_rejected_rather_than_panicking() {
        let msg = build_authenticate("wrustic", "", "hunter2", &[1u8; 8], None);
        for cut in [0, 8, 32, 63] {
            assert!(
                Authenticate::parse(&msg[..cut]).is_none(),
                "truncation at {cut} must not parse"
            );
        }
    }

    #[test]
    fn a_field_pointing_outside_the_message_is_rejected() {
        let mut msg = build_authenticate("wrustic", "", "hunter2", &[1u8; 8], None);
        // Point the NT response offset far past the end.
        msg[24..28].copy_from_slice(&0xFFFF_u32.to_le_bytes());
        assert!(Authenticate::parse(&msg).is_none());
    }
}
