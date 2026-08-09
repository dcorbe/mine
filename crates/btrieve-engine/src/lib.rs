//! Wire format for one BTRCALL, framed over a TCP stream to `btrvprobe serve`.
//!
//! ```text
//! Request   u32 frame_len | u16 op | [128] posblk | u32 datalen_in
//!                         | u32 databuf_len | databuf
//!                         | u8 keylen | i8 keynum | u32 keybuf_len | keybuf
//! Response  u32 frame_len | i16 status | [128] posblk | u32 datalen_out
//!                         | u32 databuf_len | databuf
//!                         | u32 keybuf_len | keybuf
//! ```
//!
//! `frame_len` counts everything after itself. All integers are little-endian.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub op: u16,
    pub posblk: [u8; 128],
    pub datalen: u32,
    pub databuf: Vec<u8>,
    pub keylen: u8,
    pub keynum: i8,
    pub keybuf: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: i16,
    pub posblk: [u8; 128],
    pub datalen: u32,
    pub databuf: Vec<u8>,
    pub keybuf: Vec<u8>,
}

impl Request {
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&self.op.to_le_bytes());
        body.extend_from_slice(&self.posblk);
        body.extend_from_slice(&self.datalen.to_le_bytes());
        body.extend_from_slice(&(self.databuf.len() as u32).to_le_bytes());
        body.extend_from_slice(&self.databuf);
        body.push(self.keylen);
        body.push(self.keynum as u8);
        body.extend_from_slice(&(self.keybuf.len() as u32).to_le_bytes());
        body.extend_from_slice(&self.keybuf);

        let mut frame = Vec::with_capacity(4 + body.len());
        frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
        frame.extend_from_slice(&body);
        frame
    }

    /// Decodes a frame body (the bytes after `frame_len`).
    pub fn decode(body: &[u8]) -> Result<Self, String> {
        let mut r = Reader::new(body);
        let op = r.u16()?;
        let posblk = r.array128()?;
        let datalen = r.u32()?;
        let databuf = r.vec_u32_len()?;
        let keylen = r.u8()?;
        let keynum = r.u8()? as i8;
        let keybuf = r.vec_u32_len()?;
        r.finish()?;
        Ok(Request {
            op,
            posblk,
            datalen,
            databuf,
            keylen,
            keynum,
            keybuf,
        })
    }
}

impl Response {
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&self.status.to_le_bytes());
        body.extend_from_slice(&self.posblk);
        body.extend_from_slice(&self.datalen.to_le_bytes());
        body.extend_from_slice(&(self.databuf.len() as u32).to_le_bytes());
        body.extend_from_slice(&self.databuf);
        body.extend_from_slice(&(self.keybuf.len() as u32).to_le_bytes());
        body.extend_from_slice(&self.keybuf);

        let mut frame = Vec::with_capacity(4 + body.len());
        frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
        frame.extend_from_slice(&body);
        frame
    }

    /// Decodes a frame body (the bytes after `frame_len`).
    pub fn decode(body: &[u8]) -> Result<Self, String> {
        let mut r = Reader::new(body);
        let status = r.u16()? as i16;
        let posblk = r.array128()?;
        let datalen = r.u32()?;
        let databuf = r.vec_u32_len()?;
        let keybuf = r.vec_u32_len()?;
        r.finish()?;
        Ok(Response {
            status,
            posblk,
            datalen,
            databuf,
            keybuf,
        })
    }
}

/// A cursor over a frame body that fails loudly on truncation instead of panicking.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&end| end <= self.buf.len())
            .ok_or_else(|| {
                format!(
                    "frame truncated: wanted {n} bytes at offset {}, have {}",
                    self.pos,
                    self.buf.len()
                )
            })?;
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn array128(&mut self) -> Result<[u8; 128], String> {
        Ok(self.take(128)?.try_into().unwrap())
    }

    fn vec_u32_len(&mut self) -> Result<Vec<u8>, String> {
        let len = self.u32()? as usize;
        Ok(self.take(len)?.to_vec())
    }

    fn finish(&self) -> Result<(), String> {
        if self.pos != self.buf.len() {
            return Err(format!(
                "trailing bytes: consumed {} of {}",
                self.pos,
                self.buf.len()
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_survives_the_wire() {
        let sent = Request {
            op: 5,
            posblk: [7u8; 128],
            datalen: 1998,
            databuf: vec![1, 2, 3],
            keylen: 4,
            keynum: 2,
            keybuf: vec![9, 9, 9, 9],
        };
        let bytes = sent.encode();
        assert_eq!(
            u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize,
            bytes.len() - 4,
            "the frame length counts everything after itself"
        );
        assert_eq!(Request::decode(&bytes[4..]).expect("decodes"), sent);
    }
}
