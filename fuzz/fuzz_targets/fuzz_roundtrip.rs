#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // If decode succeeds, re-encode must not panic
    if let Ok(msg) = oxirush_nas::decode_nas_5gs_message(data) {
        let _ = oxirush_nas::encode_nas_5gs_message(&msg);
    }
});
