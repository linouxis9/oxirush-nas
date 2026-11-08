//! The service-level-AA container (TS 24.501 §9.11.2.10, Table 9.11.2.10.1): each
//! parameter is the IEI of its type, then a length of one octet for a type 4 IEI, of
//! two for a type 6 IEI (70 to 7F, TS 24.007 §11.2.4), and none for a type 1 IEI
//! whose value is in its own octet. A receiver reads the parameters that it knows,
//! and the strict check the values that their clauses define.

use oxirush_nas::nas_5gs::{
    ServiceLevelAaContainer, ServiceLevelAaParameter as Parameter, ServiceLevelAaPayloadType,
    ServiceLevelAaResponse, ServiceLevelAaResponseC2AuthorizationResult as C2ar,
    ServiceLevelAaResponseResult as Slar,
};

fn container(octets: &[u8]) -> ServiceLevelAaContainer {
    ServiceLevelAaContainer::new(octets.to_vec())
}

#[test]
fn a_parameter_is_read_with_the_length_of_its_type() {
    // The response, the payload type and the service status indication have a
    // value of one octet (§9.11.2.14, §9.11.2.15 and §9.11.2.18), and no other
    let response = ServiceLevelAaResponse::new(C2ar::Successful, Slar::NotSuccessfulOrRevoked);
    for (iei, octet, parameter) in [
        (0x30, 0x06, Parameter::Response(response)),
        (
            0x40,
            0x02,
            Parameter::PayloadType(ServiceLevelAaPayloadType::C2Authorization),
        ),
        (0x50, 0x01, Parameter::ServiceStatusIndication(true)),
    ] {
        let parsed = container(&[iei, 0x01, octet]).try_parameters().unwrap();
        assert_eq!(parsed, [parameter], "{iei}");
        assert!(
            container(&[iei, 0x02, octet, 0x00])
                .try_parameters()
                .is_err(),
            "{iei}"
        );
    }
    // The payload has a length of two octets, here of no octet at the end of the
    // container, and is refused when its length is cut short
    let empty = container(&[0x70, 0x00, 0x00]);
    assert_eq!(
        empty.try_parameters().unwrap(),
        [Parameter::Payload(vec![])]
    );
    assert!(empty.validate_strict().is_ok());
    assert!(container(&[0x70, 0x00]).try_parameters().is_err());
    assert!(container(&[0x70, 0x00]).validate_strict().is_err());
}

#[test]
fn the_strict_check_takes_the_values_that_the_clauses_define() {
    let strict = |octets: &[u8]| container(octets).validate_strict().is_ok();
    // A service-level device ID of one octet at least (§9.11.2.11)
    assert!(strict(&[0x10, 0x01, b'a']));
    assert!(!strict(&[0x10, 0x00]));
    // A server address of a defined type (§9.11.2.12), which a receiver reads
    // whatever its type
    assert!(strict(&[0x20, 0x05, 0x01, 10, 0, 0, 1]));
    assert!(
        container(&[0x20, 0x02, 0x05, 0x00])
            .try_parameters()
            .is_ok()
    );
    assert!(!strict(&[0x20, 0x02, 0x05, 0x00]));
    // A response of results that are not reserved, SLAR in bits 2 and 1 and C2AR in
    // bits 4 and 3, with bits 8 to 5 spare (§9.11.2.14)
    for octet in 0..=u8::MAX {
        let defined = octet & 0xf0 == 0 && octet & 0x03 != 0x03 && (octet >> 2) & 0x03 != 0x03;
        assert_eq!(strict(&[0x30, 0x01, octet]), defined, "{octet}");
    }
    // A payload type of 1 or 2 (§9.11.2.15), followed by the payload
    assert!(strict(&[0x40, 0x01, 0x01, 0x70, 0x00, 0x01, 0xff]));
    assert!(!strict(&[0x40, 0x01, 0x03, 0x70, 0x00, 0x01, 0xff]));
    // A pending indication whose SLAPI is set, 0 being reserved (§9.11.2.17)
    assert!(strict(&[0xa1]));
    assert!(!strict(&[0xa0]));
}

#[test]
fn a_sender_writes_defined_results_and_the_length_of_each_type() {
    let response = |c2ar, slar| Parameter::Response(ServiceLevelAaResponse::new(c2ar, slar));
    let written = |parameters: &[Parameter]| {
        ServiceLevelAaContainer::from_parameters(parameters).map(|written| written.value)
    };
    let defined = response(C2ar::Successful, Slar::NotSuccessfulOrRevoked);
    assert_eq!(written(&[defined]).unwrap(), [0x30, 0x01, 0x06]);
    for (c2ar, slar) in [
        (C2ar::Reserved, Slar::Successful),
        (C2ar::Successful, Slar::Reserved),
    ] {
        let refused = ServiceLevelAaContainer::from_parameters(&[response(c2ar, slar)]);
        assert_eq!(refused.unwrap_err().member, "service-level-aa-response");
    }
    // A parameter of a type 6 IEI has a length of two octets, one of a type 4 IEI of
    // one, and one of a type 1 IEI is its own octet
    let unknown = |parameter_type, contents: &[u8]| Parameter::Unknown {
        parameter_type,
        contents: contents.to_vec(),
    };
    assert_eq!(
        written(&[unknown(0x6f, &[1, 2])]).unwrap(),
        [0x6f, 0x02, 1, 2]
    );
    assert_eq!(
        written(&[unknown(0x70, &[1, 2])]).unwrap(),
        [0x70, 0x00, 0x02, 1, 2]
    );
    assert_eq!(
        written(&[unknown(0x7f, &[1, 2])]).unwrap(),
        [0x7f, 0x00, 0x02, 1, 2]
    );
    assert_eq!(written(&[unknown(0x90, &[])]).unwrap(), [0x90]);
    assert!(written(&[unknown(0x90, &[1])]).is_err());
}
