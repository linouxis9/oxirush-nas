//! The README shows what its code prints.
//!
//! The Rust blocks of the README are documentation tests: they compile and
//! run, and nothing looks at what they print. `readme/blocks.rs` has each of
//! them as a function that prints into a string. The first test here keeps
//! that file equal to the README, and the second compares what each function
//! prints with the output that the README shows under its block.
//!
//! The output of a block is the `json` and `text` blocks that follow it with
//! nothing but blank lines between them. A block that shows no output prints
//! none.
//!
//! After a change of the code of a Rust block of the README, write the file
//! again and run the tests once more:
//!
//! ```bash
//! README_BLOCKS=write cargo test --all-features --test readme
//! cargo test --all-features --test readme
//! ```
#![cfg(all(feature = "serde", feature = "security"))]

use std::fmt::Write;

#[rustfmt::skip]
#[path = "readme/blocks.rs"]
mod blocks;

const README: &str = include_str!("../README.md");
const BLOCKS: &str = include_str!("readme/blocks.rs");
const BLOCKS_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/readme/blocks.rs");

/// A Rust block of the README: the line of its opening fence, its code, and
/// the output that the README shows under it.
struct Example {
    line: usize,
    code: String,
    output: String,
}

/// The Rust blocks of the README, each with its output.
fn examples() -> Vec<Example> {
    let mut examples: Vec<Example> = Vec::new();
    // The language of the block that is open, and whether the blocks since
    // the last Rust block are still its output.
    let mut open: Option<&str> = None;
    let mut output = false;

    for (index, line) in README.lines().enumerate() {
        match (open, line.strip_prefix("```")) {
            (None, Some("rust")) => {
                open = Some("rust");
                output = true;
                examples.push(Example {
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
                let example = examples.last_mut().unwrap();
                writeln!(example.code, "{line}").unwrap();
            }
            (Some(_), _) if output => {
                let example = examples.last_mut().unwrap();
                writeln!(example.output, "{line}").unwrap();
            }
            (Some(_), _) => {}
            // Text between two blocks ends the output of the first.
            (None, None) => output &= line.trim().is_empty(),
        }
    }
    examples
}

/// The text of `readme/blocks.rs` for the Rust blocks of the README.
fn generated(examples: &[Example]) -> String {
    let mut file = String::from(HEAD);

    // The blocks go by their rank, and not by their line: a change of the
    // text of the README leaves this file as it is.
    writeln!(file, "pub const BLOCKS: &[fn()] = &[").unwrap();
    for rank in 1..=examples.len() {
        writeln!(file, "    block_{rank},").unwrap();
    }
    writeln!(file, "];").unwrap();

    for (example, rank) in examples.iter().zip(1..) {
        writeln!(file, "\n/// The Rust block {rank} of README.md.").unwrap();
        writeln!(file, "fn block_{rank}() {{").unwrap();
        for code in example.code.lines() {
            match code.is_empty() {
                true => writeln!(file).unwrap(),
                false => writeln!(file, "    {code}").unwrap(),
            }
        }
        writeln!(file, "}}").unwrap();
    }
    file
}

const HEAD: &str = r#"// The Rust blocks of README.md, each as a function. `tests/readme.rs` writes
// this file and says how: do not edit it.
#![allow(unused)]

use std::cell::RefCell;

thread_local!(static PRINTED: RefCell<String> = const { RefCell::new(String::new()) });

// What a block prints is kept, to be compared with what the README shows.
macro_rules! println {
    () => {
        PRINTED.with(|printed| printed.borrow_mut().push('\n'))
    };
    ($($argument:tt)*) => {
        PRINTED.with(|printed| {
            let line = format!($($argument)*);
            let mut printed = printed.borrow_mut();
            printed.push_str(&line);
            printed.push('\n');
        })
    };
}

/// What `block` prints.
pub fn printed(block: fn()) -> String {
    PRINTED.with(|printed| printed.borrow_mut().clear());
    block();
    PRINTED.with(|printed| printed.take())
}

"#;

#[test]
fn the_blocks_are_those_of_the_readme() {
    let generated = generated(&examples());
    if generated == BLOCKS {
        return;
    }
    if std::env::var("README_BLOCKS").as_deref() == Ok("write") {
        std::fs::write(BLOCKS_PATH, generated).unwrap();
        panic!("tests/readme/blocks.rs is written from the README: run the tests again");
    }
    panic!(
        "tests/readme/blocks.rs is not the Rust blocks of the README: write it with \
         `README_BLOCKS=write cargo test --all-features --test readme`, then run the tests again"
    );
}

#[test]
fn each_block_prints_what_the_readme_shows() {
    let examples = examples();
    assert_eq!(examples.len(), blocks::BLOCKS.len());

    let mut differences = String::new();
    for (example, block) in examples.iter().zip(blocks::BLOCKS) {
        let printed = blocks::printed(*block);
        if printed != example.output {
            let (line, shown) = (example.line, &example.output);
            writeln!(differences, "README.md, the block of line {line} prints:").unwrap();
            writeln!(differences, "{printed}and the README shows:\n{shown}").unwrap();
        }
    }
    assert!(differences.is_empty(), "{differences}");
}
