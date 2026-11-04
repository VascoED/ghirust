//! Small formatting helpers shared by commands.

/// Format a byte count in a human-friendly way.
pub fn bytes(value: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut amount = value as f64;
    let mut unit = 0;
    while amount >= 1024.0 && unit < UNITS.len() - 1 {
        amount /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{value} B")
    } else {
        format!("{amount:.1} {}", UNITS[unit])
    }
}

/// Format a duration in milliseconds.
pub fn duration_ms(value: u128) -> String {
    if value < 1_000 {
        format!("{value} ms")
    } else {
        format!("{:.2} s", value as f64 / 1_000.0)
    }
}

/// One line of a plain-language checklist.
pub fn check(ok: bool, label: &str, detail: &str) -> String {
    let marker = if ok { "[ok]" } else { "[!]" };
    if detail.is_empty() {
        format!("{marker} {label}")
    } else {
        format!("{marker} {label} — {detail}")
    }
}
