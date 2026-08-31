// Byte-level primitives for the SMB2 wire format.
//
// SMB2 is little-endian throughout, with fixed-size structures whose variable
// parts are addressed by (offset, length) pairs measured from the start of the
// 64-byte SMB2 header. Getting a single field width wrong makes the Linux cifs
// client fail the mount with a bare -EIO, so every structure in this module is
// written field-by-field with its spec offset in a comment rather than derived
// from a Rust struct layout.
//
// Also here: the NetBIOS session framing that wraps every message, UTF-16LE
// (SMB2 paths and share names are UTF-16LE, never UTF-8), and a write-only DER
// encoder. DER is needed because SPNEGO tokens are ASN.1; we never *parse* DER
// because the only inbound token we care about is NTLMSSP, which we locate by
// scanning for its 8-byte signature instead (see session::find_ntlmssp).

use anyhow::{Result, bail};

// SMB2 over TCP keeps the 4-byte NetBIOS session header: one zero byte, then a
// 24-bit big-endian payload length. Direct-TCP SMB2 allows up to 16 MiB, but we
// cap inbound messages far lower — nothing a read-only client sends is large,
// and the cap bounds per-connection allocation from an unauthenticated peer.
pub(crate) const NBSS_HEADER_LEN: usize = 4;
pub(crate) const MAX_INBOUND_MESSAGE: usize = 1024 * 1024;

pub(crate) fn nbss_header(len: usize) -> [u8; NBSS_HEADER_LEN] {
    let len = len as u32;
    [0, (len >> 16) as u8, (len >> 8) as u8, len as u8]
}

/// Payload length from a NetBIOS session header, or `None` if the header is not
/// one this transport accepts.
///
/// Direct-TCP SMB2 requires the first byte to be zero — a session *message*.
/// The NBT session service on port 139 uses other values there (0x81 session
/// request, 0x85 keepalive), and reading one of those as a length prefix turns
/// a wrong-transport client into a confusing SMB2 parse failure several steps
/// later instead of a clean refusal here.
pub(crate) fn nbss_len(hdr: &[u8; NBSS_HEADER_LEN]) -> Option<usize> {
    if hdr[0] != 0 {
        return None;
    }
    Some(((hdr[1] as usize) << 16) | ((hdr[2] as usize) << 8) | hdr[3] as usize)
}

/// Cursor over an inbound message. Every accessor is bounds-checked and returns
/// `Err` rather than panicking: the input is attacker-controlled in the sense
/// that any process on the loopback interface can connect.
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// How many bytes have been consumed. Only tests look at this — they use it
    /// to assert a parser consumed exactly its structure's fixed size, which is
    /// what catches a field added to a codec but not to its reader.
    #[cfg(test)]
    pub(crate) fn pos(&self) -> usize {
        self.pos
    }

    pub(crate) fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            bail!("short read: want {n} bytes, {} remain", self.remaining());
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub(crate) fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    pub(crate) fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        self.take(n)
    }

    pub(crate) fn skip(&mut self, n: usize) -> Result<()> {
        self.take(n).map(|_| ())
    }

    /// Read a variable-length field addressed by an absolute offset from the
    /// start of the enclosing SMB2 message. Offsets in SMB2 are message-
    /// relative, not structure-relative, so callers pass the raw field value.
    ///
    /// A zero offset or zero length yields an empty slice — clients legitimately
    /// send both to mean "absent" (e.g. an empty security buffer).
    pub(crate) fn slice_at(&self, offset: usize, len: usize) -> Result<&'a [u8]> {
        if offset == 0 || len == 0 {
            return Ok(&[]);
        }
        let end = offset
            .checked_add(len)
            .ok_or_else(|| anyhow::anyhow!("offset {offset} + length {len} overflows"))?;
        if end > self.buf.len() {
            bail!(
                "field at offset {offset} length {len} runs past the {}-byte message",
                self.buf.len()
            );
        }
        Ok(&self.buf[offset..end])
    }
}

/// Append-only byte buffer with in-place patching, for building responses whose
/// offset/length fields are only known after the variable part is written.
pub(crate) struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub(crate) fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub(crate) fn with_capacity(n: usize) -> Self {
        Self {
            buf: Vec::with_capacity(n),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.buf.len()
    }

    pub(crate) fn into_vec(self) -> Vec<u8> {
        self.buf
    }

    pub(crate) fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub(crate) fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub(crate) fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub(crate) fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub(crate) fn bytes(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }

    pub(crate) fn zeros(&mut self, n: usize) {
        self.buf.resize(self.buf.len() + n, 0);
    }

    /// Pad with zeros until the length is a multiple of `align`. Compounded
    /// SMB2 responses must start on an 8-byte boundary.
    pub(crate) fn align_to(&mut self, align: usize) {
        while !self.buf.len().is_multiple_of(align) {
            self.buf.push(0);
        }
    }

    pub(crate) fn patch_u32(&mut self, at: usize, v: u32) {
        self.buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
}

impl Default for Writer {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) fn utf16le(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 2);
    for unit in s.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

/// Decode a UTF-16LE field. Unpaired surrogates are replaced rather than
/// rejected — a malformed share name should produce a clean "no such share"
/// rather than tearing down the connection.
pub(crate) fn from_utf16le(b: &[u8]) -> Result<String> {
    if !b.len().is_multiple_of(2) {
        bail!("UTF-16LE field has odd length {}", b.len());
    }
    let units: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    Ok(String::from_utf16_lossy(&units))
}

/// Wrap `body` in a DER tag-length-value. Only the definite-length short and
/// two-byte long forms are emitted; SPNEGO tokens here never exceed 64 KiB.
pub(crate) fn der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 4);
    out.push(tag);
    let len = body.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    }
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nbss_length_round_trips() {
        for len in [0usize, 1, 255, 256, 65535, 65536, 0xFF_FFFF] {
            assert_eq!(nbss_len(&nbss_header(len)), Some(len), "length {len}");
        }
    }

    /// Direct-TCP SMB2 carries only session messages. An NBT type byte from a
    /// port-139 client must be refused rather than read as part of a length.
    #[test]
    fn nbss_rejects_a_non_session_message() {
        for ty in [0x81u8, 0x82, 0x83, 0x85] {
            assert_eq!(nbss_len(&[ty, 0, 0, 8]), None, "type {ty:#04x}");
        }
        assert_eq!(nbss_len(&[0, 0, 0, 8]), Some(8));
    }

    #[test]
    fn nbss_header_keeps_the_leading_zero_byte() {
        assert_eq!(nbss_header(0x00_1234), [0x00, 0x00, 0x12, 0x34]);
    }

    #[test]
    fn reader_rejects_reads_past_the_end() {
        let mut r = Reader::new(&[1, 2, 3]);
        assert_eq!(r.u16().unwrap(), 0x0201);
        assert!(r.u16().is_err(), "must not read past the buffer");
        assert_eq!(r.remaining(), 1);
    }

    #[test]
    fn reader_decodes_little_endian_widths() {
        let buf = [0xEF, 0xBE, 0xAD, 0xDE, 0x01, 0x02, 0x03, 0x04];
        let mut r = Reader::new(&buf);
        assert_eq!(r.u32().unwrap(), 0xDEAD_BEEF);
        assert_eq!(r.pos(), 4);
        let mut r = Reader::new(&buf);
        assert_eq!(r.u64().unwrap(), 0x0403_0201_DEAD_BEEF);
    }

    #[test]
    fn slice_at_treats_zero_offset_or_length_as_absent() {
        let r = Reader::new(&[1, 2, 3, 4]);
        assert!(r.slice_at(0, 4).unwrap().is_empty());
        assert!(r.slice_at(2, 0).unwrap().is_empty());
    }

    #[test]
    fn slice_at_rejects_out_of_range_and_overflowing_fields() {
        let r = Reader::new(&[1, 2, 3, 4]);
        assert_eq!(r.slice_at(1, 3).unwrap(), &[2, 3, 4]);
        assert!(r.slice_at(1, 4).is_err(), "runs one byte past the end");
        assert!(r.slice_at(usize::MAX, 2).is_err(), "offset+len overflows");
    }

    #[test]
    fn writer_patches_fields_in_place() {
        let mut w = Writer::new();
        let at = w.len();
        w.u32(0);
        w.bytes(b"payload");
        w.patch_u32(at, 0xDEAD_BEEF);
        let v = w.into_vec();
        assert_eq!(&v[0..4], &[0xEF, 0xBE, 0xAD, 0xDE]);
        assert_eq!(&v[4..], b"payload");
    }

    #[test]
    fn align_to_pads_to_the_next_boundary_and_is_idempotent() {
        let mut w = Writer::new();
        w.bytes(&[0; 5]);
        w.align_to(8);
        assert_eq!(w.len(), 8);
        w.align_to(8);
        assert_eq!(w.len(), 8, "already aligned, must not pad again");
    }

    #[test]
    fn utf16le_round_trips_including_non_bmp() {
        for s in ["", "snap", "naïve", "日本語", "emoji \u{1F600}"] {
            assert_eq!(from_utf16le(&utf16le(s)).unwrap(), s, "input {s:?}");
        }
    }

    #[test]
    fn from_utf16le_rejects_odd_lengths() {
        assert!(from_utf16le(&[0x41]).is_err());
    }

    #[test]
    fn der_tlv_selects_the_shortest_length_form() {
        assert_eq!(der_tlv(0x04, &[]), vec![0x04, 0x00]);
        assert_eq!(der_tlv(0x04, &[0xAA; 5])[..2], [0x04, 0x05]);
        // 0x80..=0xFF use the one-byte long form.
        assert_eq!(der_tlv(0x04, &[0xAA; 200])[..3], [0x04, 0x81, 200]);
        // Above 0xFF, the two-byte big-endian long form.
        assert_eq!(der_tlv(0x04, &[0xAA; 300])[..4], [0x04, 0x82, 0x01, 0x2C]);
    }

    #[test]
    fn der_tlv_length_matches_the_body() {
        let body = [0xAA; 300];
        let tlv = der_tlv(0x30, &body);
        assert_eq!(tlv.len(), 4 + body.len());
        assert_eq!(&tlv[4..], &body[..]);
    }
}
