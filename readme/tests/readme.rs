//! The README and the documentation show what their code prints.
//!
//! Their Rust blocks are documentation tests of the crate: they compile and run, and
//! nothing there looks at what they print. The build script writes each block as a
//! function that prints into a string, and the test compares it with the output that
//! its page shows under it (`build.rs` says how).

#![allow(unused)]

include!(concat!(env!("OUT_DIR"), "/blocks.rs"));

#[test]
fn each_block_prints_what_its_page_shows() {
    let mut differences = String::new();
    for Block {
        page,
        line,
        run,
        shown,
    } in BLOCKS
    {
        let printed = printed(*run);
        if printed != *shown {
            differences += &format!(
                "{page}, the block of line {line} prints:\n{printed}and the page shows:\n{shown}\n"
            );
        }
    }
    assert!(
        !BLOCKS.is_empty() && differences.is_empty(),
        "{differences}"
    );
}
