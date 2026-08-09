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

/// The frame `Drop` sends to tell `btrvprobe serve` to exit: `frame_len = 2`
/// followed by `op = 0xFFFF`. Every other field a real `Request` carries is
/// irrelevant to a quit, and `serve_one` in btrvprobe.c never looks past `op`
/// for this value.
const QUIT_FRAME: [u8; 6] = [2, 0, 0, 0, 0xFF, 0xFF];

/// A running `btrvprobe.exe serve` under Wine, and the one connection to it.
/// Stateless per the wire format's design: `call` sends whatever `posblk` the
/// caller supplies and returns whatever the engine sends back, so cursor
/// state lives in the caller, not here.
pub struct Engine {
    child: std::process::Child,
    stream: std::net::TcpStream,
}

impl Engine {
    /// Starts `wine btrvprobe.exe serve <port>` in the Btrieve Wine prefix,
    /// waits for it to report readiness, and connects. The port is picked by
    /// binding `127.0.0.1:0` and reading back what the OS assigned, so two
    /// `Engine`s never collide and a stale server from a previous run is
    /// never talked to by mistake.
    pub fn spawn() -> Result<Self, String> {
        use std::io::BufRead;

        let prefix = std::env::var("BTRIEVE_WINEPREFIX").or_else(|_| {
            std::env::var("HOME")
                .map(|home| format!("{home}/.btrieve-wine"))
                .map_err(|_| "neither $BTRIEVE_WINEPREFIX nor $HOME is set".to_string())
        })?;
        let exe = format!("{prefix}/drive_c/btrieve/btrvprobe.exe");
        let port = pick_port()?;

        let mut child = std::process::Command::new("wine")
            .arg(&exe)
            .arg("serve")
            .arg(port.to_string())
            .env("WINEPREFIX", &prefix)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| format!("spawning wine {exe}: {e}"))?;

        let stdout = child.stdout.take().expect("stdout was piped");
        let mut reader = std::io::BufReader::new(stdout);
        let mut line = String::new();
        loop {
            line.clear();
            let n = reader
                .read_line(&mut line)
                .map_err(|e| format!("reading btrvprobe's stdout: {e}"))?;
            if n == 0 {
                let _ = child.kill();
                return Err("btrvprobe exited before printing 'listening'".to_string());
            }
            if line.trim_start().starts_with("listening") {
                break;
            }
        }

        let stream = std::net::TcpStream::connect(("127.0.0.1", port))
            .map_err(|e| format!("connecting to btrvprobe on port {port}: {e}"))?;

        Ok(Engine { child, stream })
    }

    /// Sends one `Request` and returns the matching `Response`.
    pub fn call(&mut self, req: Request) -> Result<Response, String> {
        use std::io::{Read, Write};

        self.stream
            .write_all(&req.encode())
            .map_err(|e| format!("writing request: {e}"))?;

        let mut len_bytes = [0u8; 4];
        self.stream
            .read_exact(&mut len_bytes)
            .map_err(|e| format!("reading response frame_len: {e}"))?;
        let frame_len = u32::from_le_bytes(len_bytes) as usize;

        let mut body = vec![0u8; frame_len];
        self.stream
            .read_exact(&mut body)
            .map_err(|e| format!("reading response body: {e}"))?;

        Response::decode(&body)
    }
}

impl Drop for Engine {
    /// Tells the server to quit, then kills the process regardless of
    /// whether it took the hint. A leaked `W32MKDE.EXE` still holding the
    /// file handle is the failure mode that makes the *next* run mysterious,
    /// not this one.
    fn drop(&mut self) {
        use std::io::Write;
        let _ = self.stream.write_all(&QUIT_FRAME);
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn pick_port() -> Result<u16, String> {
    let listener =
        std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| format!("picking a port: {e}"))?;
    listener
        .local_addr()
        .map(|addr| addr.port())
        .map_err(|e| format!("reading the picked port: {e}"))
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
