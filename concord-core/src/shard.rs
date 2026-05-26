//! Shard merkle root per [RFC 0001 §Shards](https://github.com/Concordfaces/rfcs/blob/main/0001-manifest.md#shards).
//!
//! A shard's identifier is the `blake3` merkle root of its chunk-hash
//! sequence, computed bottom-up with a fixed 2-ary tree, leaves padded
//! with the all-zero hash when the chunk count is not a power of two.
//!
//! This is deliberately simple: fixed arity, fixed leaf order (the order
//! chunks appear in the source artifact), zero-hash padding. Two
//! independent implementations of RFC 0001 must produce the same root for
//! the same input chunk sequence.

use crate::chunker::ChunkHash;

/// All-zero leaf used to pad to the next power of two.
pub const ZERO_LEAF: ChunkHash = ChunkHash::from_bytes([0u8; 32]);

/// Hash two child nodes into a parent node using blake3 over the 64-byte
/// concatenation. Caller decides leaf/internal order.
fn hash_pair(left: &ChunkHash, right: &ChunkHash) -> ChunkHash {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left.as_bytes());
    buf[32..].copy_from_slice(right.as_bytes());
    ChunkHash::of(&buf)
}

/// Compute the shard merkle root from a sequence of chunk hashes.
///
/// - Empty input → all-zero hash (the `ZERO_LEAF` constant).
/// - Single chunk → that chunk's hash unchanged (per the convention that a
///   single-element tree's root is the leaf itself; this avoids a wasted
///   hash and matches common merkle conventions).
/// - Otherwise pad the leaf vector with `ZERO_LEAF` to the next power of
///   two, then reduce pairwise bottom-up until a single root remains.
pub fn shard_merkle(chunks: &[ChunkHash]) -> ChunkHash {
    if chunks.is_empty() {
        return ZERO_LEAF;
    }
    if chunks.len() == 1 {
        return chunks[0];
    }

    // Pad to next power of two with ZERO_LEAF.
    let mut level: Vec<ChunkHash> = chunks.to_vec();
    let target = level.len().next_power_of_two();
    level.resize(target, ZERO_LEAF);

    // Reduce.
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks_exact(2) {
            next.push(hash_pair(&pair[0], &pair[1]));
        }
        level = next;
    }

    level[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunker::ChunkHash;

    fn h(seed: u8) -> ChunkHash {
        ChunkHash::of(&[seed])
    }

    #[test]
    fn empty_is_zero_leaf() {
        let root = shard_merkle(&[]);
        assert_eq!(root, ZERO_LEAF);
        assert_eq!(root.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn single_chunk_is_itself() {
        let only = h(1);
        assert_eq!(shard_merkle(&[only]), only);
    }

    #[test]
    fn two_chunks_pair_directly() {
        let a = h(1);
        let b = h(2);
        let expected = hash_pair(&a, &b);
        assert_eq!(shard_merkle(&[a, b]), expected);
    }

    #[test]
    fn three_chunks_pad_to_four() {
        let a = h(1);
        let b = h(2);
        let c = h(3);
        // pad with ZERO_LEAF
        let lvl1_left = hash_pair(&a, &b);
        let lvl1_right = hash_pair(&c, &ZERO_LEAF);
        let expected = hash_pair(&lvl1_left, &lvl1_right);
        assert_eq!(shard_merkle(&[a, b, c]), expected);
    }

    #[test]
    fn four_chunks_no_padding() {
        let a = h(1);
        let b = h(2);
        let c = h(3);
        let d = h(4);
        let lvl1_left = hash_pair(&a, &b);
        let lvl1_right = hash_pair(&c, &d);
        let expected = hash_pair(&lvl1_left, &lvl1_right);
        assert_eq!(shard_merkle(&[a, b, c, d]), expected);
    }

    #[test]
    fn order_matters() {
        let a = h(1);
        let b = h(2);
        assert_ne!(shard_merkle(&[a, b]), shard_merkle(&[b, a]));
    }

    #[test]
    fn deterministic_across_runs() {
        let chunks: Vec<ChunkHash> = (1..=13).map(h).collect();
        let r1 = shard_merkle(&chunks);
        let r2 = shard_merkle(&chunks);
        assert_eq!(r1, r2);
    }

    #[test]
    fn duplicate_chunks_collapse_at_leaf_but_not_at_root() {
        // Two identical chunks at the leaf level produce identical leaves,
        // so the root is the hash of that leaf concatenated with itself.
        let a = h(1);
        let expected = hash_pair(&a, &a);
        assert_eq!(shard_merkle(&[a, a]), expected);
    }
}
