//! Each Rust block of the pages as a function that prints into a string, with the output
//! that its page shows under it, in `$OUT_DIR/blocks.rs`.
//!
//! A page is the README, or the documentation of a module: the `//!` lines of its file.
//! A block that is checked opens with ` ```rust `, or with ` ```rust,ignore ` for one
//! that uses other crates of the family, which the documentation tests of the crate do
//! not have and this package has. Its output is the
//! `json` and `text` blocks that follow it with nothing but blank lines between them,
//! and a block that shows no output prints none. A block that has a `main` is run as
//! the documentation test runs it: its function calls `main`, which returns a `Result`,
//! and an error fails the test.

use std::fmt::Write;
use std::path::Path;

/// The pages, from the root of the crate: the README, and the files whose module
/// documentation has the examples that the README links to.
const PAGES: &[&str] = &[
    "README.md",
    "src/lib.rs",
    "src/nas_eps/mod.rs",
    "src/nas_5gs/security.rs",
    "src/nas_eps/security.rs",
    "src/paths.rs",
];

/// A Rust block of a page: its page, the line of its opening fence, its code, and the
/// output that the page shows under it.
struct Example {
    page: &'static str,
    line: usize,
    code: String,
    output: String,
}

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut examples = Vec::new();
    for page in PAGES {
        let path = root.join(page);
        println!("cargo:rerun-if-changed={}", path.display());
        let text = std::fs::read_to_string(&path).expect("a page");
        examples.extend(examples_of(page, &text));
    }
    let out = Path::new(&std::env::var("OUT_DIR").expect("OUT_DIR")).join("blocks.rs");
    std::fs::write(out, generated(&examples)).expect("blocks.rs");
}

/// The Rust blocks of a page, each with its output.
fn examples_of(page: &'static str, text: &str) -> Vec<Example> {
    let documentation = page.ends_with(".rs");
    let mut examples: Vec<Example> = Vec::new();
    // The language of the block that is open, and whether the blocks since the last
    // Rust block are still its output.
    let mut open: Option<&str> = None;
    let mut output = false;
    for (index, line) in text.lines().enumerate() {
        // The page of a file is the lines of its module documentation.
        let line = match (documentation, line.strip_prefix("//!")) {
            (false, _) => line,
            (true, Some(line)) => line.strip_prefix(' ').unwrap_or(line),
            (true, None) => continue,
        };
        match (open, line.strip_prefix("```")) {
            (None, Some("rust" | "rust,ignore")) => {
                open = Some("rust");
                output = true;
                examples.push(Example {
                    page,
                    line: index + 1,
                    code: String::new(),
                    output: String::new(),
                });
            }
            (None, Some(language)) => {
                open = Some(language);
                output &= matches!(language, "json" | "text");
            }
            (Some(_), Some("")) => open = None,
            (Some("rust"), _) => {
                // A line that the documentation hides is code all the same.
                let code = match documentation {
                    true => line.strip_prefix("# ").unwrap_or(line),
                    false => line,
                };
                let example = examples.last_mut().expect("an open block");
                writeln!(example.code, "{code}").unwrap();
            }
            (Some(_), _) if output => {
                let example = examples.last_mut().expect("an open block");
                writeln!(example.output, "{line}").unwrap();
            }
            (Some(_), _) => {}
            // Text between two blocks ends the output of the first.
            (None, None) => output &= line.trim().is_empty(),
        }
    }
    examples
}

/// The functions of the blocks, and `BLOCKS`: each with its page, its line and its output.
fn generated(examples: &[Example]) -> String {
    let mut file = String::from(HEAD);
    writeln!(file, "pub const BLOCKS: &[Block] = &[").unwrap();
    for (example, rank) in examples.iter().zip(1..) {
        let (page, line, output) = (example.page, example.line, &example.output);
        writeln!(
            file,
            "    Block {{ page: {page:?}, line: {line}, run: block_{rank}, shown: {output:?} }},"
        )
        .unwrap();
    }
    writeln!(file, "];").unwrap();
    for (example, rank) in examples.iter().zip(1..) {
        writeln!(file, "\nfn block_{rank}() {{\n{}", example.code).unwrap();
        // The `main` of a block is what the block does.
        if example
            .code
            .lines()
            .any(|code| code.starts_with("fn main("))
        {
            writeln!(file, "main().unwrap();").unwrap();
        }
        writeln!(file, "}}").unwrap();
    }
    file
}

const HEAD: &str = r#"
use std::cell::RefCell;

thread_local!(static PRINTED: RefCell<String> = const { RefCell::new(String::new()) });

// What a block prints is kept, to be compared with what its page shows.
macro_rules! print {
    ($($argument:tt)*) => {{
        let text = format!($($argument)*);
        PRINTED.with(|printed| printed.borrow_mut().push_str(&text))
    }};
}

macro_rules! println {
    () => {
        print!("\n")
    };
    ($($argument:tt)*) => {{
        let line = format!($($argument)*);
        print!("{line}\n")
    }};
}

/// A Rust block of a page: its page, the line of its opening fence, the function of its
/// code, and the output that the page shows under it.
pub struct Block {
    pub page: &'static str,
    pub line: usize,
    pub run: fn(),
    pub shown: &'static str,
}

/// What `block` prints.
pub fn printed(block: fn()) -> String {
    PRINTED.with(|printed| printed.borrow_mut().clear());
    block();
    PRINTED.with(|printed| printed.take())
}

"#;
