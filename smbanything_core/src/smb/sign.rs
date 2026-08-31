// SMB 2.1 message signing (MS-SMB2 3.1.4.1).
//
// For dialect 2.x the signing key *is* the NTLM session key, and the signature
// is the first 16 bytes of HMAC-SHA256 over the whole PDU with the Signature
// field zeroed. (3.x replaces this with an AES-CMAC over a KDF-derived key —
// another reason to stay on 2.1.)
//
// Compounded messages are signed per PDU, not once for the whole buffer: each
// chained response is hashed over its own extent, from its header to wherever
// NextCommand points. Signing the buffer as a unit would produce a signature
// Windows rejects on every compound, which is most of what it sends.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use super::proto::{HEADER_LEN, SMB2_MAGIC, flags};

type HmacSha256 = Hmac<Sha256>;

/// Offset of the 16-byte Signature field within an SMB2 header.
const SIGNATURE_OFFSET: usize = 48;
const SIGNATURE_LEN: usize = 16;

/// Compute the signature for one PDU. `pdu` must start at its SMB2 header.
fn signature(key: &[u8; 16], pdu: &[u8]) -> [u8; SIGNATURE_LEN] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC takes any key length");
    // Everything before the Signature field, then 16 zero bytes in its place,
    // then the remainder. Copying the PDU just to zero 16 bytes would double
    // the allocation on every read response.
    mac.update(&pdu[..SIGNATURE_OFFSET]);
    mac.update(&[0u8; SIGNATURE_LEN]);
    mac.update(&pdu[SIGNATURE_OFFSET + SIGNATURE_LEN..]);

    let full = mac.finalize().into_bytes();
    let mut out = [0u8; SIGNATURE_LEN];
    out.copy_from_slice(&full[..SIGNATURE_LEN]);
    out
}

/// Walk the PDUs chained inside `buf` by NextCommand, yielding each one's
/// (start, end). Stops at the first malformed link rather than looping.
fn pdu_extents(buf: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    loop {
        if buf.len() < offset + HEADER_LEN || buf[offset..offset + 4] != SMB2_MAGIC {
            break;
        }
        let next = u32::from_le_bytes(
            buf[offset + 20..offset + 24]
                .try_into()
                .expect("4 bytes present"),
        ) as usize;
        // Checked: `next` is a client-supplied u32, so on a 32-bit target
        // `offset + next` can wrap and turn an out-of-bounds link into one that
        // passes the range check. An overflow is just an invalid link.
        let end = offset.checked_add(next);
        if next == 0 || next < HEADER_LEN || end.is_none_or(|end| end > buf.len()) {
            out.push((offset, buf.len()));
            break;
        }
        let offset_end = end.expect("checked above");
        out.push((offset, offset_end));
        offset = offset_end;
    }
    out
}

/// Sign every PDU in `buf` in place and set the SIGNED flag on each.
pub(crate) fn sign(key: &[u8; 16], buf: &mut [u8]) {
    for (start, end) in pdu_extents(buf) {
        // Set SIGNED before hashing: the flag is part of the signed bytes, so
        // setting it afterwards would invalidate the signature we just wrote.
        let flag_at = start + 16;
        let current = u32::from_le_bytes(buf[flag_at..flag_at + 4].try_into().expect("4 bytes"));
        buf[flag_at..flag_at + 4].copy_from_slice(&(current | flags::SIGNED).to_le_bytes());

        let sig = signature(key, &buf[start..end]);
        let sig_at = start + SIGNATURE_OFFSET;
        buf[sig_at..sig_at + SIGNATURE_LEN].copy_from_slice(&sig);
    }
}

/// Verify every PDU in `buf`.
///
/// Called once a session holds a key, which happens only on a successful NTLMv2
/// authentication. The messages before that — NEGOTIATE and the SESSION_SETUP
/// legs themselves — have no key to check against and are not routed here.
///
/// An unsigned PDU is **rejected**, not skipped. Skipping it would mean anyone
/// able to reach the port could clear the SIGNED flag and have their requests
/// accepted unverified — precisely the downgrade signing exists to stop. Once a
/// session is signed, every message in it must be signed.
///
/// The one exception is the keepalive: a PDU that names no session at all
/// (SessionId 0) and is an ECHO. MS-SMB2 3.3.5.2.4 scopes signature
/// verification to the session in the header, and Samba implements exactly
/// that — its check runs only once the session id resolves to a session
/// (`smb2_server.c:3096-3105`, `:3189`). cifs.ko sends its keepalive with a
/// NULL tcon and so an unsigned, session-0 header every `echo_interval`;
/// refusing it drops the connection that keepalive exists to hold open, and it
/// reaches nothing privileged — ECHO is answered with a fixed acknowledgement.
///
/// SESSION_SETUP is deliberately *not* exempt, though it too is legitimately
/// unsigned. It only ever needs to be when the connection has no key yet, and
/// this function is not called then: the caller verifies with the key held
/// before the message is processed, so a connection still logging in never
/// reaches here. Exempting it would therefore only ever admit an unsigned
/// SESSION_SETUP on a connection that is already authenticated — letting anyone
/// able to inject a packet restart the NTLM exchange under the live session,
/// replace its outstanding challenge, and spend the server-wide logon-failure
/// budget on responses they could not sign for. Samba can allow it because a
/// session-0 SESSION_SETUP there opens a *new* session beside the existing one;
/// here there is one session per connection, so it lands on the live one.
pub(crate) fn verify(key: &[u8; 16], buf: &[u8]) -> Verdict {
    use super::proto::cmd;

    let extents = pdu_extents(buf);
    if extents.is_empty() {
        // Not a well-formed SMB2 buffer, so there is nothing to trust.
        return Verdict::Malformed;
    }
    for (start, end) in extents {
        let flag_at = start + 16;
        let flags_val = u32::from_le_bytes(
            buf[flag_at..flag_at + 4]
                .try_into()
                .expect("4 bytes present"),
        );
        let command = u16::from_le_bytes(buf[start + 12..start + 14].try_into().expect("2 bytes"));
        let session_id =
            u64::from_le_bytes(buf[start + 40..start + 48].try_into().expect("8 bytes"));

        if flags_val & flags::SIGNED == 0 {
            if session_id == 0 && command == cmd::ECHO {
                continue;
            }
            return Verdict::Unsigned(command);
        }

        // `signature` reads nothing from the Signature field — it hashes the
        // bytes before it, sixteen zeros, then the bytes after — so the PDU is
        // hashed where it lies rather than copied to blank the field.
        let expected = signature(key, &buf[start..end]);
        let sig_at = start + SIGNATURE_OFFSET;
        let received = &buf[sig_at..sig_at + SIGNATURE_LEN];

        if received.ct_eq(&expected[..]).unwrap_u8() == 0 {
            return Verdict::Mismatch(command);
        }
    }
    Verdict::Valid
}

/// Outcome of verification. Carries the command so a rejection is diagnosable:
/// "which message failed, and was it unsigned or wrong" is the whole question
/// when a client silently disconnects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Valid,
    /// The PDU carried no SIGNED flag.
    Unsigned(u16),
    /// The signature did not match.
    Mismatch(u16),
    /// Not a parseable SMB2 buffer.
    Malformed,
}

impl Verdict {
    pub(crate) fn is_valid(self) -> bool {
        matches!(self, Self::Valid)
    }

    pub(crate) fn describe(self) -> String {
        use super::proto::cmd;
        match self {
            Self::Valid => "valid".to_string(),
            Self::Unsigned(c) => format!("{} arrived unsigned", cmd::name(c)),
            Self::Mismatch(c) => format!("{} signature mismatch", cmd::name(c)),
            Self::Malformed => "not a parseable SMB2 message".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smb::proto::cmd;
    use crate::smb::wire::Writer;

    /// One SMB2 PDU: header plus `body_len` bytes of body.
    fn pdu(next_command: u32, body_len: usize) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&SMB2_MAGIC);
        w.u16(HEADER_LEN as u16);
        w.u16(1); // CreditCharge
        w.u32(0); // Status
        w.u16(cmd::ECHO);
        w.u16(1); // Credits
        w.u32(0); // Flags
        w.u32(next_command);
        w.u64(42); // MessageId
        w.u32(0); // Reserved
        w.u32(0); // TreeId
        w.u64(7); // SessionId
        w.zeros(16); // Signature
        for i in 0..body_len {
            w.u8(i as u8);
        }
        w.into_vec()
    }

    fn flags_of(buf: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(buf[at + 16..at + 20].try_into().unwrap())
    }

    #[test]
    fn signing_sets_the_flag_and_fills_the_signature() {
        let key = [0x11u8; 16];
        let mut buf = pdu(0, 8);
        assert_eq!(&buf[SIGNATURE_OFFSET..SIGNATURE_OFFSET + 16], &[0u8; 16]);

        sign(&key, &mut buf);
        assert_ne!(
            &buf[SIGNATURE_OFFSET..SIGNATURE_OFFSET + 16],
            &[0u8; 16],
            "signature must be written"
        );
        assert_eq!(flags_of(&buf, 0) & flags::SIGNED, flags::SIGNED);
        assert!(
            verify(&key, &buf).is_valid(),
            "our own signature must verify"
        );
    }

    #[test]
    fn a_wrong_key_fails_verification() {
        let mut buf = pdu(0, 8);
        sign(&[0x11u8; 16], &mut buf);
        assert!(!verify(&[0x22u8; 16], &buf).is_valid());
    }

    #[test]
    fn tampering_with_the_body_fails_verification() {
        let key = [0x33u8; 16];
        let mut buf = pdu(0, 8);
        sign(&key, &mut buf);
        assert!(verify(&key, &buf).is_valid());

        let last = buf.len() - 1;
        buf[last] ^= 0x01;
        assert!(
            !verify(&key, &buf).is_valid(),
            "a body edit must be detected"
        );
    }

    #[test]
    fn tampering_with_the_header_fails_verification() {
        let key = [0x44u8; 16];
        let mut buf = pdu(0, 8);
        sign(&key, &mut buf);
        // Change the MessageId, which is inside the signed range.
        buf[24] ^= 0xFF;
        assert!(!verify(&key, &buf).is_valid());
    }

    #[test]
    fn the_signed_flag_is_covered_by_the_signature() {
        // The flag sits inside the hashed range, so it must be set *before*
        // hashing. Setting it afterwards would emit a signature every client
        // rejects.
        let key = [0x55u8; 16];
        let mut with_flag = pdu(0, 8);
        let flag_at = 16;
        let f = u32::from_le_bytes(with_flag[flag_at..flag_at + 4].try_into().unwrap());
        with_flag[flag_at..flag_at + 4].copy_from_slice(&(f | flags::SIGNED).to_le_bytes());

        let without_flag = pdu(0, 8);
        assert_ne!(
            signature(&key, &with_flag),
            signature(&key, &without_flag),
            "SIGNED must change the computed signature"
        );
    }

    #[test]
    fn an_unsigned_pdu_is_rejected_once_a_session_is_signed() {
        // Otherwise clearing one flag bit bypasses authentication entirely.
        let buf = pdu(0, 8);
        assert!(!verify(&[0x66u8; 16], &buf).is_valid());
    }

    /// Only cifs.ko's session-less keepalive may arrive unsigned on a keyed
    /// connection. An unsigned SESSION_SETUP is legitimate only *before* the
    /// connection has a key, and this function is not called then — so admitting
    /// one here would only ever admit an injected packet restarting the NTLM
    /// exchange under a live authenticated session.
    #[test]
    fn only_the_session_less_keepalive_is_exempt_from_signing() {
        let key = [0xABu8; 16];
        let unsigned = |command: u16, session_id: u64| {
            let mut buf = pdu(0, 8);
            buf[12..14].copy_from_slice(&command.to_le_bytes());
            buf[40..48].copy_from_slice(&session_id.to_le_bytes());
            verify(&key, &buf)
        };

        assert_eq!(unsigned(cmd::ECHO, 0), Verdict::Valid, "the keepalive");
        assert_eq!(
            unsigned(cmd::ECHO, 7),
            Verdict::Unsigned(cmd::ECHO),
            "an ECHO inside the session is signed like everything else"
        );
        assert_eq!(
            unsigned(cmd::SESSION_SETUP, 0),
            Verdict::Unsigned(cmd::SESSION_SETUP),
            "a keyed connection has already logged in; this can only be injected"
        );
    }

    #[test]
    fn stripping_the_signed_flag_does_not_bypass_verification() {
        let key = [0x88u8; 16];
        let mut buf = pdu(0, 8);
        sign(&key, &mut buf);
        assert!(verify(&key, &buf).is_valid());

        let flag_at = 16;
        let f = u32::from_le_bytes(buf[flag_at..flag_at + 4].try_into().unwrap());
        buf[flag_at..flag_at + 4].copy_from_slice(&(f & !flags::SIGNED).to_le_bytes());
        assert!(
            !verify(&key, &buf).is_valid(),
            "downgrade attempt must be refused"
        );
    }

    #[test]
    fn each_pdu_in_a_compound_is_signed_separately() {
        let key = [0x77u8; 16];

        // Two chained PDUs. The first is 64 + 8 = 72 bytes, already 8-aligned.
        let first_len = HEADER_LEN + 8;
        let mut buf = pdu(first_len as u32, 8);
        buf.extend_from_slice(&pdu(0, 16));

        let extents = pdu_extents(&buf);
        assert_eq!(extents.len(), 2, "chain must be walked");
        assert_eq!(extents[0], (0, first_len));
        assert_eq!(extents[1], (first_len, buf.len()));

        sign(&key, &mut buf);
        assert!(verify(&key, &buf).is_valid());
        assert_eq!(flags_of(&buf, 0) & flags::SIGNED, flags::SIGNED);
        assert_eq!(flags_of(&buf, first_len) & flags::SIGNED, flags::SIGNED);

        // The two signatures differ — each covers only its own PDU.
        assert_ne!(
            &buf[SIGNATURE_OFFSET..SIGNATURE_OFFSET + 16],
            &buf[first_len + SIGNATURE_OFFSET..first_len + SIGNATURE_OFFSET + 16]
        );

        // Tampering with only the second PDU must still be caught.
        let last = buf.len() - 1;
        buf[last] ^= 0x01;
        assert!(!verify(&key, &buf).is_valid());
    }

    #[test]
    fn a_chain_pointing_out_of_bounds_terminates() {
        // A malformed NextCommand must not loop or panic.
        let buf = pdu(0xFFFF, 8);
        let extents = pdu_extents(&buf);
        assert_eq!(extents, vec![(0, buf.len())]);
    }

    #[test]
    fn a_chain_pointing_backwards_terminates() {
        let buf = pdu(8, 8); // NextCommand smaller than a header
        let extents = pdu_extents(&buf);
        assert_eq!(extents, vec![(0, buf.len())]);
    }

    #[test]
    fn a_non_smb2_buffer_yields_no_extents_and_fails_verification() {
        assert!(pdu_extents(b"not smb2 at all").is_empty());
        // Nothing to verify means nothing to trust, so this is a refusal rather
        // than a vacuous pass.
        assert!(!verify(&[0u8; 16], b"not smb2 at all").is_valid());
    }

    #[test]
    fn signatures_are_stable_for_the_same_input() {
        let key = [0x99u8; 16];
        let mut a = pdu(0, 8);
        let mut b = pdu(0, 8);
        sign(&key, &mut a);
        sign(&key, &mut b);
        assert_eq!(a, b);
    }
}
