/*
   OxiRush
   Copyright 2025-2026 Valentin D'Emmanuele

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

//! The blocks of the README that use other crates of the family show what
//! their code prints.
//!
//! Such a block opens with ` ```rust,ignore `: the tests of the crate, which
//! have none of the other crates, skip it, and this package, which has them,
//! runs it. `readme/blocks.rs` has each of them as a function that prints
//! into a string. The first test here keeps that file equal to the README,
//! and the second compares what each function prints with the output that
//! the README shows under its block: the `json` and `text` blocks that
//! follow it with nothing but blank lines between them. A block that defines
//! `main` is run through it.
//!
//! After a change of the code of such a block, write the file again and run
//! the tests once more, in this directory:
//!
//! ```bash
//! README_BLOCKS=write cargo test
//! cargo test
//! ```

use std::fmt::Write;

#[rustfmt::skip]
#[path = "readme/blocks.rs"]
mod blocks;

const README: &str = include_str!("../../README.md");
const BLOCKS: &str = include_str!("readme/blocks.rs");
const BLOCKS_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/readme/blocks.rs");

/// The fence that opens a block of this package.
const FENCE: &str = "rust,ignore";

/// A block of the README: the line of its opening fence, its code, and the
/// output that the README shows under it.
struct Example {
    line: usize,
    code: String,
    output: String,
}

/// The blocks of the README that open with [`FENCE`], each with its output.
fn examples() -> Vec<Example> {
    let mut examples: Vec<Example> = Vec::new();
    // The language of the block that is open, and whether the blocks since
    // the last block of this package are still its output.
    let mut open: Option<&str> = None;
    let mut output = false;
    for (index, line) in README.lines().enumerate() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        match (open, line.strip_prefix("```")) {
            (None, Some(FENCE)) => {
                open = Some(FENCE);
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
            (Some(FENCE), _) => writeln!(examples.last_mut().unwrap().code, "{line}").unwrap(),
            (Some(_), _) if output => {
                writeln!(examples.last_mut().unwrap().output, "{line}").unwrap()
            }
            (Some(_), _) => {}
            // Text between two blocks ends the output of the first.
            (None, None) => output &= line.trim().is_empty(),
        }
    }
    examples
}

/// The text of `readme/blocks.rs` for the blocks of the README.
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
        writeln!(
            file,
            "\n/// The block {rank} of the README that uses other crates."
        )
        .unwrap();
        writeln!(file, "fn block_{rank}() {{").unwrap();
        for code in example.code.lines() {
            match code.is_empty() {
                true => writeln!(file).unwrap(),
                false => writeln!(file, "    {code}").unwrap(),
            }
        }
        // A block that is a program is run through its `main`.
        if example.code.contains("fn main() -> ") {
            writeln!(file, "    main().unwrap();").unwrap();
        } else if example.code.contains("fn main()") {
            writeln!(file, "    main();").unwrap();
        }
        writeln!(file, "}}").unwrap();
    }
    file
}

const HEAD: &str = r#"// The blocks of the README that use other crates of the family, each as a
// function. `tests/readme.rs` writes this file and says how: do not edit it.
#![allow(unused)]

use std::cell::RefCell;

thread_local!(static PRINTED: RefCell<String> = const { RefCell::new(String::new()) });

// What a block prints is kept, to be compared with what the README shows.
macro_rules! println {
    () => {
        PRINTED.with(|printed| printed.borrow_mut().push('\n'))
    };
    // The line is made first, where the block is: its arguments may have a
    // `?` or an `await`.
    ($($argument:tt)*) => {{
        let line = format!($($argument)*);
        PRINTED.with(|printed| {
            let mut printed = printed.borrow_mut();
            printed.push_str(&line);
            printed.push('\n');
        })
    }};
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
    let examples = examples();
    assert!(
        !examples.is_empty(),
        "the README has no block that opens with ```{FENCE}"
    );
    let generated = generated(&examples);
    // A checkout may have changed the line endings.
    if generated == BLOCKS.replace('\r', "") {
        return;
    }
    if std::env::var("README_BLOCKS").as_deref() == Ok("write") {
        std::fs::write(BLOCKS_PATH, generated).unwrap();
        panic!("tests/readme/blocks.rs is written from the README: run the tests again");
    }
    panic!(
        "tests/readme/blocks.rs is not the blocks of the README: write it with \
         `README_BLOCKS=write cargo test`, then run the tests again"
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
            writeln!(differences, "the block of line {line} prints:").unwrap();
            writeln!(differences, "{printed}and the README shows:\n{shown}").unwrap();
        }
    }
    assert!(differences.is_empty(), "{differences}");
}
