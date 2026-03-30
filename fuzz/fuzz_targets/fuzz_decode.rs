#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must not panic on any input
    let _ = oxirush_nas::decode_nas_5gs_message(data);
});
