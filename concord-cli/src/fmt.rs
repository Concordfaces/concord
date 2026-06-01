//! Tiny human-facing formatters for the CLI summary lines.

/// Format a byte count as a human-readable IEC string (`B`, `KiB`, `MiB`,
/// `GiB`, `TiB`), matching how HuggingFace / `du -h` present sizes. Two
/// decimals above the byte level; whole numbers for raw bytes.
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut val = n as f64;
    let mut unit = 0;
    while val >= 1024.0 && unit < UNITS.len() - 1 {
        val /= 1024.0;
        unit += 1;
    }
    format!("{val:.2} {}", UNITS[unit])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_raw_bytes_without_decimals() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1023), "1023 B");
    }

    #[test]
    fn formats_kib_and_mib() {
        assert_eq!(human_bytes(1024), "1.00 KiB");
        assert_eq!(human_bytes(1536), "1.50 KiB");
        assert_eq!(human_bytes(1024 * 1024), "1.00 MiB");
    }

    #[test]
    fn formats_gib_and_tib() {
        assert_eq!(human_bytes(3 * 1024 * 1024 * 1024), "3.00 GiB");
        assert_eq!(human_bytes(1024u64.pow(4)), "1.00 TiB");
    }

    #[test]
    fn caps_at_tib() {
        // 2048 TiB stays in TiB rather than inventing a PiB unit.
        assert_eq!(human_bytes(2048 * 1024u64.pow(4)), "2048.00 TiB");
    }
}
