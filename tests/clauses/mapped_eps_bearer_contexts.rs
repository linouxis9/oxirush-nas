//! The mapped EPS bearer contexts (TS 24.501 §9.11.4.8): each context the EPS bearer
//! identity in bits 8 to 5, its length in two octets, the operation code in bits 8
//! and 7 of the next octet, the E bit in bit 5 and the number of parameters in bits 4
//! to 1, then each parameter: its identifier, its length and its contents. Creation
//! takes the E bit and parameters, deletion neither, modification parameters.

use oxirush_nas::nas_5gs::{
    MappedEpsBearerContext as Context, MappedEpsBearerContexts as Contexts,
    MappedEpsBearerOpCode as Op, MappedEpsBearerParam as Param, MappedEpsBearerParamId as ParamId,
};

fn octets(text: &str) -> Vec<u8> {
    hex::decode(text.split_whitespace().collect::<String>()).unwrap()
}

/// An extended APN-AMBR of six octets (identifier 5).
fn ambr() -> Param {
    Param {
        param_id: 0x05,
        contents: vec![0x03, 0x00, 0x01, 0x03, 0x00, 0x01],
    }
}

#[test]
fn the_codes_of_a_context_are_those_of_its_table() {
    let operations = [Op::Reserved, Op::Create, Op::Delete, Op::Modify];
    for (code, operation) in (0..).zip(operations) {
        assert_eq!(Op::try_from(code & 0x03).ok(), Some(operation));
    }
    let identifiers = [
        ParamId::EpsQos,
        ParamId::ExtendedEpsQos,
        ParamId::TrafficFlowTemplate,
        ParamId::ApnAmbr,
        ParamId::ExtendedApnAmbr,
    ];
    for (code, identifier) in (1..).zip(identifiers) {
        assert_eq!(ParamId::try_from(code).ok(), Some(identifier));
    }
    // The extended EPS QoS has ten octets and the extended APN-AMBR six
    for (param_id, length, well_formed) in
        [(2, 10, true), (2, 9, false), (5, 6, true), (5, 5, false)]
    {
        let param = Param {
            param_id,
            contents: vec![0; length],
        };
        assert_eq!(param.is_well_formed(), well_formed, "{param_id} {length}");
    }
}

#[test]
fn an_operation_has_the_e_bit_and_the_parameters_of_its_row() {
    let context = |eps_bearer_id, operation, e_flag, params| {
        Context::new(eps_bearer_id, operation, e_flag, params).is_ok()
    };
    assert!(context(5, Op::Create, true, vec![ambr()]));
    assert!(!context(5, Op::Create, false, vec![ambr()]));
    assert!(context(5, Op::Delete, false, vec![]));
    assert!(!context(5, Op::Delete, false, vec![ambr()]));
    assert!(context(5, Op::Modify, false, vec![ambr()]));
    // An EPS bearer identity of 5 to 15, and parameters of their lengths
    assert!(!context(4, Op::Create, true, vec![ambr()]));
    let short = Param {
        param_id: 0x05,
        contents: vec![0; 5],
    };
    assert!(!context(5, Op::Create, true, vec![short]));
}

#[test]
fn a_context_ends_where_its_length_says() {
    // EPS bearer identity 5, created with the E bit and the extended APN-AMBR and the
    // extended EPS QoS; then 6, deleted
    let value = octets(
        "50 0015 52 05 06 030001030001 02 0a 00000000000000000000  \
         60 0001 80",
    );
    let received = Contexts::new(value);
    let contexts = received.contexts().unwrap();
    assert_eq!(contexts.len(), 2);
    assert!(contexts[0].e_flag && !contexts[1].e_flag);
    assert_eq!(contexts[0].params[0], ambr());
    assert_eq!(contexts[0].params[1].contents, [0; 10]);
    assert!(received.is_well_formed() && received.receiver_syntax_is_valid());
    assert!(!Contexts::new(octets("50 0002 80 00")).receiver_syntax_is_valid());
    // A modification without the E bit, read as written
    let modify = Contexts::new(octets("50 0009 c1 05 06 030001030001"));
    assert!(!modify.contexts().unwrap()[0].e_flag);
}
