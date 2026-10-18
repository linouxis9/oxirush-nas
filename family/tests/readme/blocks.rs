// The blocks of the README that use other crates of the family, each as a
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

pub const BLOCKS: &[fn()] = &[
    block_1,
];

/// The block 1 of the README that uses other crates.
fn block_1() {
    use oxirush_nas::{nas_5gs::Nas5gsMessage, nas_eps::NasEpsMessage};
    use oxirush_ngap::{build_ngap, extract_ngap_ies, ngap::NASPDU};
    use oxirush_s1ap::build_s1ap;

    fn main() -> Result<(), Box<dyn std::error::Error>> {
        // The AMF: a REGISTRATION REJECT, cause #22, in a DOWNLINK NAS TRANSPORT
        let reject = Nas5gsMessage::decode(&hex::decode("7e0044165f012a")?)?;
        let downlink = build_ngap!(InitiatingMessage, DownlinkNASTransport, DownlinkNASTransport,
            AMF_UE_NGAP_ID(1u64),
            RAN_UE_NGAP_ID(7u32),
            NAS_PDU(reject.encode()?),
        )?;
        println!("{}", downlink.to_tree());

        // The gNB gives the UE the NAS-PDU, which decodes as the message
        extract_ngap_ies!(downlink, DownlinkNASTransport,
            req nas: NASPDU = NAS_PDU(nas) => nas,
        );
        println!("{}", Nas5gsMessage::decode(&nas.0)?);

        // The MME: an ATTACH REJECT, cause #3, in a DOWNLINK NAS TRANSPORT of S1AP
        let reject = NasEpsMessage::decode(&[0x07, 0x44, 0x03])?;
        let downlink = build_s1ap!(InitiatingMessage, downlinkNASTransport, DownlinkNASTransport,
            MME_UE_S1AP_ID(1u32),
            eNB_UE_S1AP_ID(7u32),
            NAS_PDU(reject.encode()?),
        )?;
        println!("{}", downlink.to_tree());
        Ok(())
    }
    main().unwrap();
}
