//! Fixed-boundary blake3 chunker per [RFC 0001 §Chunking](https://github.com/Concordfaces/rfcs/blob/main/0001-manifest.md#chunking).
//!
//! Boundaries are fixed at `CHUNK_SIZE` (4 MiB). Fixed beats content-defined
//! here because model weights don't have insertion-heavy editing patterns,
//! and fixed boundaries make dedup deterministic across publishers and
//! operators with no shared state.
//!
//! Each chunk is identified by its `blake3` hash, hex-lowered, prefixed
//! with `b3:`. Example: `b3:7a4e9c2f…`.

use std::fmt;
use std::io::{self, Read};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::CHUNK_SIZE;

/// A blake3 chunk identifier, e.g. `b3:7a4e9c2f9b1d…`.
///
/// Display + FromStr round-trip via the `b3:<64-hex>` form. Bytes are the
/// raw 32-byte blake3 hash.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub struct ChunkHash([u8; 32]);

impl ChunkHash {
    pub const fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Hash the supplied bytes with blake3 in one shot.
    pub fn of(data: &[u8]) -> Self {
        Self(*blake3::hash(data).as_bytes())
    }
}

impl fmt::Display for ChunkHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "b3:{}", hex::encode(self.0))
    }
}

impl fmt::Debug for ChunkHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Keep debug short; print the full hex via Display when needed.
        write!(f, "ChunkHash({})", self)
    }
}

#[derive(Debug, Error)]
pub enum ChunkHashParseError {
    #[error("expected `b3:` prefix")]
    MissingPrefix,
    #[error("expected 64 hex chars after prefix, got {0}")]
    BadHexLen(usize),
    #[error("invalid hex: {0}")]
    BadHex(#[from] hex::FromHexError),
}

impl FromStr for ChunkHash {
    type Err = ChunkHashParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let rest = s
            .strip_prefix("b3:")
            .ok_or(ChunkHashParseError::MissingPrefix)?;
        if rest.len() != 64 {
            return Err(ChunkHashParseError::BadHexLen(rest.len()));
        }
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(rest, &mut bytes)?;
        Ok(Self(bytes))
    }
}

impl From<ChunkHash> for String {
    fn from(h: ChunkHash) -> Self {
        h.to_string()
    }
}

impl TryFrom<String> for ChunkHash {
    type Error = ChunkHashParseError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

/// A single chunk emitted by [`Chunker`]: the hash, where it sat in the
/// source stream, and how many bytes it covers.
///
/// The chunk *bytes themselves* are not held by this struct — callers
/// stream them straight into storage. Holding them in memory across a
/// large model push would dwarf the host's RAM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkRef {
    pub hash: ChunkHash,
    pub offset: u64,
    pub len: u32,
}

/// Errors that can come out of the chunker.
#[derive(Debug, Error)]
pub enum ChunkerError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

/// Streaming fixed-4-MiB chunker. Calls `on_chunk` for each emitted chunk
/// with `(ChunkRef, &[u8])` so the caller can stream the bytes into storage
/// without holding them in memory.
///
/// Returns the full list of [`ChunkRef`]s (without bodies) for assembly
/// into a [`crate::shard::ShardMerkle`] later.
pub fn chunk_stream<R: Read, F: FnMut(ChunkRef, &[u8]) -> Result<(), ChunkerError>>(
    mut src: R,
    mut on_chunk: F,
) -> Result<Vec<ChunkRef>, ChunkerError> {
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut chunks = Vec::new();
    let mut offset: u64 = 0;

    loop {
        // Fill buf or hit EOF. read() may return short reads even
        // before EOF (especially on pipes), so loop until full or EOF.
        let mut filled = 0usize;
        while filled < CHUNK_SIZE {
            let n = src.read(&mut buf[filled..])?;
            if n == 0 {
                break; // EOF
            }
            filled += n;
        }

        if filled == 0 {
            break;
        }

        let slice = &buf[..filled];
        let hash = ChunkHash::of(slice);
        let cref = ChunkRef {
            hash,
            offset,
            len: filled as u32,
        };
        on_chunk(cref, slice)?;
        chunks.push(cref);
        offset += filled as u64;

        if filled < CHUNK_SIZE {
            break; // last chunk, smaller than CHUNK_SIZE
        }
    }

    Ok(chunks)
}

/// Convenience wrapper: chunk a slice in memory. Returns the chunk refs
/// plus each chunk's bytes by reference into the original slice.
pub fn chunk_slice(data: &[u8]) -> Vec<(ChunkRef, &[u8])> {
    let mut out = Vec::new();
    let mut offset: u64 = 0;
    for body in data.chunks(CHUNK_SIZE) {
        let hash = ChunkHash::of(body);
        out.push((
            ChunkRef {
                hash,
                offset,
                len: body.len() as u32,
            },
            body,
        ));
        offset += body.len() as u64;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn chunk_hash_round_trip() {
        let h = ChunkHash::of(b"hello");
        let s = h.to_string();
        assert!(s.starts_with("b3:"));
        assert_eq!(s.len(), 3 + 64);
        let parsed: ChunkHash = s.parse().unwrap();
        assert_eq!(h, parsed);
    }

    #[test]
    fn empty_input_yields_no_chunks() {
        let refs = chunk_stream(Cursor::new(&[][..]), |_, _| Ok(())).unwrap();
        assert!(refs.is_empty());
        let mem = chunk_slice(&[]);
        assert!(mem.is_empty());
    }

    #[test]
    fn exact_one_chunk_boundary() {
        let data = vec![0xABu8; CHUNK_SIZE];
        let mut received = Vec::new();
        let refs = chunk_stream(Cursor::new(&data[..]), |c, body| {
            received.push((c, body.to_vec()));
            Ok(())
        })
        .unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].len as usize, CHUNK_SIZE);
        assert_eq!(refs[0].offset, 0);
        assert_eq!(received[0].1.len(), CHUNK_SIZE);
        // Stream + slice agree on hash.
        let mem = chunk_slice(&data);
        assert_eq!(refs[0].hash, mem[0].0.hash);
    }

    #[test]
    fn exact_one_chunk_plus_remainder() {
        let data = vec![0x41u8; CHUNK_SIZE + 17];
        let refs = chunk_stream(Cursor::new(&data[..]), |_, _| Ok(())).unwrap();
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].len as usize, CHUNK_SIZE);
        assert_eq!(refs[1].len, 17);
        assert_eq!(refs[1].offset as usize, CHUNK_SIZE);
    }

    #[test]
    fn multiple_full_chunks() {
        let data = vec![0x55u8; CHUNK_SIZE * 3];
        let refs = chunk_stream(Cursor::new(&data[..]), |_, _| Ok(())).unwrap();
        assert_eq!(refs.len(), 3);
        // All same bytes → all same hash, demonstrating dedup at the chunk
        // layer (storage would skip after the first).
        assert_eq!(refs[0].hash, refs[1].hash);
        assert_eq!(refs[1].hash, refs[2].hash);
        assert_eq!(refs[0].offset, 0);
        assert_eq!(refs[1].offset as usize, CHUNK_SIZE);
        assert_eq!(refs[2].offset as usize, CHUNK_SIZE * 2);
    }

    #[test]
    fn stream_matches_slice() {
        // Pseudo-random-ish bytes (deterministic for reproducibility).
        let n = CHUNK_SIZE * 2 + 1234;
        let data: Vec<u8> = (0..n).map(|i| (i * 31 + 7) as u8).collect();

        let stream_refs = chunk_stream(Cursor::new(&data[..]), |_, _| Ok(())).unwrap();
        let mem_pairs = chunk_slice(&data);

        assert_eq!(stream_refs.len(), mem_pairs.len());
        for (s, m) in stream_refs.iter().zip(mem_pairs.iter()) {
            assert_eq!(s.hash, m.0.hash);
            assert_eq!(s.offset, m.0.offset);
            assert_eq!(s.len, m.0.len);
        }
    }

    #[test]
    fn short_reads_dont_fracture_chunks() {
        // ShortReader returns 1 byte at a time. Ensures the inner fill
        // loop coalesces them into CHUNK_SIZE-sized chunks.
        struct ShortReader<'a>(&'a [u8]);
        impl<'a> Read for ShortReader<'a> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.0.is_empty() {
                    return Ok(0);
                }
                let n = 1.min(buf.len());
                buf[..n].copy_from_slice(&self.0[..n]);
                self.0 = &self.0[n..];
                Ok(n)
            }
        }

        let data = vec![0x99u8; CHUNK_SIZE + 5];
        let refs = chunk_stream(ShortReader(&data), |_, _| Ok(())).unwrap();
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].len as usize, CHUNK_SIZE);
        assert_eq!(refs[1].len, 5);
    }

    #[test]
    fn parse_errors() {
        assert!("not-a-hash".parse::<ChunkHash>().is_err());
        assert!("b3:short".parse::<ChunkHash>().is_err());
        assert!("b3:zzzz".parse::<ChunkHash>().is_err());
    }
}
