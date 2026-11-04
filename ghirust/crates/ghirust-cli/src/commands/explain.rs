//! `ghirust explain`

use anyhow::Result;

struct Topic {
    key: &'static str,
    title: &'static str,
    summary: &'static str,
    body: &'static str,
}

const TOPICS: &[Topic] = &[
    Topic {
        key: "function",
        title: "Function",
        summary: "A named block of machine code with an entry point.",
        body: "A function is a reusable piece of code. In a stripped binary the original name is usually \
gone, so reverse-engineering tools create names such as FUN_00401000. The number is the address \
where the function starts. When you see a function in GHIRUST, the address tells you exactly where \
it lives in the program.",
    },
    Topic {
        key: "decompiler",
        title: "Decompiler",
        summary: "Turns assembly into readable C-like code.",
        body: "A disassembler shows the CPU instructions one by one. A decompiler goes further: it \
reconstructs variables, loops, if statements and function calls so the result looks like C. The \
output is a best-effort reconstruction, not the original source code. Names, types and comments \
may be guesses.",
    },
    Topic {
        key: "index",
        title: "Search index",
        summary: "A small map that makes repeated searches fast.",
        body: "Instead of rereading every file for every query, GHIRUST records file names, sizes and \
function boundaries once. A search then memory-maps the text and scans it with SIMD instructions. \
This is why the first search may take a moment (the index is built), while later searches are \
much faster.",
    },
    Topic {
        key: "export",
        title: "Streaming export",
        summary: "Writes results as they are produced instead of building one giant string.",
        body: "Older exporters can hold the complete decompilation in memory before saving. A 30 MB \
DLL can produce more than 100 MB of C text, which means a very large allocation and a long pause. \
GHIRUST writes each function to disk immediately, keeps only a small buffer, and checkpoints its \
progress. The file appears atomically when the export finishes.",
    },
    Topic {
        key: "cfg",
        title: "Control-flow graph (CFG)",
        summary: "A map of the possible paths through a function.",
        body: "A CFG splits a function into basic blocks and draws arrows for jumps and branches. It \
helps both humans and analysis algorithms understand loops, error paths and unreachable code.",
    },
    Topic {
        key: "symbol",
        title: "Symbol",
        summary: "A name attached to an address.",
        body: "Symbols can be functions, global variables, imports or debug names. A stripped binary \
has few or no symbols, so tools infer names from imports, signatures, strings and call patterns.",
    },
    Topic {
        key: "ghidra",
        title: "Ghidra",
        summary: "The open-source reverse-engineering framework GHIRUST learns from.",
        body: "Ghidra is a mature Java/Swing application with a C++ decompiler. GHIRUST reuses its \
analysis ideas and, in the first phase, its headless backend. The goal is a Rust-first core with \
faster search, a gentler learning curve and bounded-memory export.",
    },
    Topic {
        key: "false-positive",
        title: "False positive",
        summary: "A result that looks meaningful but is not.",
        body: "Automated analysis can guess a function boundary or a type incorrectly. GHIRUST labels \
inferred information with a confidence level and always keeps confirmed metadata separate from \
guesses.",
    },
];

/// Print a glossary entry or list every topic.
pub fn run(topic: Option<&str>, json: bool) -> Result<()> {
    let Some(topic) = topic else {
        if json {
            let items: Vec<_> = TOPICS
                .iter()
                .map(|topic| {
                    serde_json::json!({
                        "topic": topic.key,
                        "title": topic.title,
                        "summary": topic.summary,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&items)?);
        } else {
            println!("GHIRUST glossary\n");
            for topic in TOPICS {
                println!("  {:<14} {}", topic.key, topic.summary);
            }
            println!("\nRun `ghirust explain <topic>` for the full explanation.");
        }
        return Ok(());
    };

    let key = topic.to_ascii_lowercase();
    let Some(entry) = TOPICS.iter().find(|entry| entry.key == key) else {
        anyhow::bail!(
            "unknown topic '{topic}'. Available topics: {}",
            TOPICS
                .iter()
                .map(|entry| entry.key)
                .collect::<Vec<_>>()
                .join(", ")
        );
    };

    if json {
        let payload = serde_json::json!({
            "topic": entry.key,
            "title": entry.title,
            "summary": entry.summary,
            "body": entry.body,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        println!("{} — {}\n", entry.title, entry.summary);
        for line in wrap(entry.body, 88) {
            println!("{line}");
        }
    }
    Ok(())
}

fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if !current.is_empty() && current.len() + 1 + word.len() > width {
            lines.push(current);
            current = String::new();
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}
