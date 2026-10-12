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

//! The initial NAS message of a UE that has a security context (TS 24.501
//! §4.4.6): its cleartext IEs alone, and the complete message ciphered in
//! its NAS message container. The vectors of `fixtures/initial-nas.tsv`
//! are computed without this crate, by the program beside them.
#![cfg(feature = "security")]

use oxirush_nas::nas_5gs::ie::{CipheringAlgorithm, IntegrityAlgorithm};
use oxirush_nas::nas_5gs::*;
use oxirush_nas::nas_eps as e;

struct Vector {
    name: &'static str,
    kamf: KAmf,
    nea: CipheringAlgorithm,
    count: NasCount,
    complete: Vec<u8>,
    protected: Vec<u8>,
}

fn vectors() -> impl Iterator<Item = Vector> {
    let octets = |hex: &str| hex::decode(hex).unwrap();
    include_str!("fixtures/initial-nas.tsv")
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(move |line| {
            let fields: Vec<&str> = line.split('\t').collect();
            assert_eq!(fields[2], "2", "{line}");
            Vector {
                name: fields[0],
                kamf: KAmf::from_slice(&octets(fields[1])).unwrap(),
                nea: CipheringAlgorithm::from_u8(fields[3].parse().unwrap()).unwrap(),
                count: NasCount::new(fields[4].parse().unwrap()).unwrap(),
                complete: octets(fields[5]),
                protected: octets(fields[6]),
            }
        })
}

/// A context whose next uplink NAS COUNT over 3GPP access is `count`.
fn context(vector: &Vector) -> NasSecurityContext {
    let zero = Some(NasCount::ZERO);
    NasSecurityContext::restore_from_kamf(
        &vector.kamf,
        IntegrityAlgorithm::NIA2,
        vector.nea,
        (Some(vector.count), zero),
        (zero, zero),
    )
    .unwrap()
}

/// The UE writes the octets of each vector, and the AMF reads the complete
/// message back from them, with the message as it was sent beside it.
#[test]
fn an_initial_message_is_sent_and_read_as_the_vectors_have_it() {
    let mut seen = 0;
    for vector in vectors() {
        let name = vector.name;
        let complete = Nas5gsMessage::decode(&vector.complete).unwrap();
        let mut ue = context(&vector);
        let sent = ue.protect_initial(&complete).unwrap();
        assert_eq!(hex::encode(&sent), hex::encode(&vector.protected), "{name}");
        let next = ue.nas_count(Direction::Uplink, NasConnection::ThreeGpp);
        assert_eq!(next, vector.count.next().ok(), "{name}");

        let mut amf = context(&vector);
        let verified = amf.unprotect(&vector.protected, Direction::Uplink).unwrap();
        assert_eq!(verified.message, complete, "{name}");
        assert_eq!(verified.count, vector.count, "{name}");
        assert_eq!(
            verified.security_header_type,
            Nas5gsSecurityHeaderType::IntegrityProtected
        );
        // What was sent is the plain message under the header
        let cleartext = Nas5gsMessage::decode(&vector.protected[7..]).unwrap();
        match name.contains("cleartext") {
            true => assert_eq!((verified.sent, &cleartext), (None, &complete), "{name}"),
            false => assert_eq!(verified.sent, Some(cleartext), "{name}"),
        }
        let mut amf = context(&vector);
        let raw = (amf.unprotect_raw(&vector.protected, Direction::Uplink)).unwrap();
        assert_eq!(raw.message, vector.complete, "{name}");
        match name.contains("cleartext") {
            true => assert_eq!(raw.sent, None, "{name}"),
            false => assert_eq!(raw.sent.as_deref(), Some(&vector.protected[7..]), "{name}"),
        }
        seen += 1;
    }
    assert_eq!(seen, 12);
}

/// What the cleartext IEs are: every other IE of the four messages goes in
/// the container, and an IE that is cleartext stays beside it.
#[test]
fn the_cleartext_ies_are_those_of_the_clause() {
    let kamf = KAmf::new(&[7; 32]);
    let context = || {
        let (nia, nea) = (IntegrityAlgorithm::NIA2, CipheringAlgorithm::NEA2);
        NasSecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap()
    };
    let sent = |complete: &Nas5gsMessage| {
        let sent = context().protect_initial(complete).unwrap();
        let Nas5gsMessage::SecurityProtected(_, sent) = Nas5gsMessage::decode(&sent).unwrap()
        else {
            panic!("{complete:?}");
        };
        let received = context().unprotect(
            &context().protect_initial(complete).unwrap(),
            Direction::Uplink,
        );
        assert_eq!(&received.unwrap().message, complete);
        *sent
    };
    // The REGISTRATION REQUEST with every optional IE of the fixtures: the
    // UE security capability, the additional GUTI and the like stay, and
    // the 5GMM capability, the requested NSSAI and the like do not
    let fixtures = include_str!("fixtures/nas-5gs.tsv");
    let fixture = |name: &str| {
        let line = fixtures
            .lines()
            .find(|line| line.split('\t').next() == Some(name));
        hex::decode(line.unwrap().split('\t').nth(1).unwrap()).unwrap()
    };
    let Nas5gsMessage::Gmm(header, Nas5gmmMessage::RegistrationRequest(mut request)) =
        Nas5gsMessage::decode(&fixture("RegistrationRequest-optional")).unwrap()
    else {
        panic!()
    };
    request.nas_message_container = None;
    request.nid = Some(NasNid::from_nid_value("000007ed9d5b").unwrap());
    let complete = Nas5gsMessage::Gmm(header, Nas5gmmMessage::RegistrationRequest(request.clone()));
    let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationRequest(cleartext)) = sent(&complete)
    else {
        panic!()
    };
    assert_eq!(
        cleartext.fgs_registration_type,
        request.fgs_registration_type
    );
    assert_eq!(cleartext.fgs_mobile_identity, request.fgs_mobile_identity);
    assert_eq!(
        cleartext.ue_security_capability,
        request.ue_security_capability
    );
    assert_eq!(cleartext.additional_guti, request.additional_guti);
    assert_eq!(cleartext.nid, request.nid);
    assert!(request.ue_security_capability.is_some() && request.additional_guti.is_some());
    assert!(request.fgmm_capability.is_some() && cleartext.fgmm_capability.is_none());
    assert!(request.requested_nssai.is_some() && cleartext.requested_nssai.is_none());
    assert!(request.uplink_data_status.is_some() && cleartext.uplink_data_status.is_none());
    assert!(cleartext.nas_message_container.is_some());
    // Nothing else than the cleartext IEs and the container
    let mut only = NasRegistrationRequest::new(
        request.fgs_registration_type.clone(),
        request.fgs_mobile_identity.clone(),
    );
    only.ue_security_capability = request.ue_security_capability.clone();
    only.additional_guti = request.additional_guti.clone();
    only.ue_status = request.ue_status.clone();
    only.eps_nas_message_container = request.eps_nas_message_container.clone();
    only.nid = request.nid.clone();
    only.nas_message_container = cleartext.nas_message_container.clone();
    assert_eq!(*cleartext, only);

    // An IE that the message table does not have is ciphered too
    let mut octets = fixture("ServiceRequest");
    octets.extend_from_slice(&[0x39, 0x01, 0xaa]);
    let complete = Nas5gsMessage::decode(&octets).unwrap();
    let Nas5gsMessage::Gmm(_, Nas5gmmMessage::ServiceRequest(cleartext)) = sent(&complete) else {
        panic!()
    };
    assert!(cleartext.unknown_ies.is_empty() && cleartext.nas_message_container.is_some());

    // A CONTROL PLANE SERVICE REQUEST with a CIoT small data container and
    // another IE has a container, and the small data in it
    let small = NasCiotSmallDataContainer::new(vec![0x05, 0xa1, 0xb2]);
    let request = NasControlPlaneServiceRequest::new(NasControlPlaneServiceType::new(1))
        .with_ciot_small_data_container(small)
        .with_pdu_session_status(NasPduSessionStatus::from_sessions(&[5]).unwrap());
    let complete = Nas5gsMessage::new_5gmm(request);
    let Nas5gsMessage::Gmm(_, Nas5gmmMessage::ControlPlaneServiceRequest(cleartext)) =
        sent(&complete)
    else {
        panic!()
    };
    assert!(cleartext.ciot_small_data_container.is_none());
    assert!(cleartext.pdu_session_status.is_none() && cleartext.nas_message_container.is_some());
}

/// What is no initial NAS message, or is not one to protect, is refused and
/// uses no COUNT, and a container that is not the message is refused once
/// its code is verified.
#[test]
fn what_is_no_initial_message_is_refused() {
    let kamf = KAmf::new(&[7; 32]);
    let (nia, nea) = (IntegrityAlgorithm::NIA2, CipheringAlgorithm::NEA2);
    let mut ue = NasSecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
    let refused = |ue: &mut NasSecurityContext, octets: &[u8]| {
        let message = Nas5gsMessage::decode(octets).unwrap();
        ue.protect_initial(&message).unwrap_err().to_string()
    };
    // A REGISTRATION COMPLETE, a 5GSM message, a message that has its container
    assert_eq!(
        refused(&mut ue, &[0x7e, 0x00, 0x43]),
        "cannot encode: RegistrationComplete is no initial NAS message: REGISTRATION REQUEST, \
         DEREGISTRATION REQUEST from the UE, SERVICE REQUEST and CONTROL PLANE SERVICE REQUEST are"
    );
    assert_eq!(
        refused(&mut ue, &[0x2e, 0x05, 0x01, 0xd4]),
        "cannot encode: an initial NAS message is a plain 5GMM message"
    );
    let contained = hex::decode("7e004c010007f400421122334471000d7e004c010007f4004211223344");
    assert_eq!(
        refused(&mut ue, &contained.unwrap()),
        "cannot encode: the NAS message container of an initial NAS message is made by the \
         security context: the message is given without one"
    );
    assert_eq!(
        ue.nas_count(Direction::Uplink, NasConnection::ThreeGpp),
        Some(NasCount::ZERO)
    );

    // A SERVICE REQUEST whose container has a REGISTRATION REQUEST, ciphered
    // as a UE ciphers one with the same COUNT: the code is right, and the
    // message is refused
    let registration = hex::decode("7e004101000d0102f8390000000021436587f950022000").unwrap();
    let registration = Nas5gsMessage::decode(&registration).unwrap();
    let mut other = NasSecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
    let contained = other.protect_initial(&registration).unwrap();
    let Nas5gsMessage::SecurityProtected(_, contained) = Nas5gsMessage::decode(&contained).unwrap()
    else {
        panic!()
    };
    let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationRequest(contained)) = *contained else {
        panic!()
    };
    let value = contained.nas_message_container.unwrap().value;
    let service = NasServiceRequest::new(
        NasKeySetIdentifier::new(0x10),
        NasFGsMobileIdentity::new(hex::decode("f4004211223344").unwrap()),
    )
    .with_nas_message_container(NasMessageContainer::new(value));
    let integrity_protected = Nas5gsSecurityHeaderType::IntegrityProtected;
    let sent = (ue.protect(
        &Nas5gsMessage::new_5gmm(service),
        integrity_protected,
        Direction::Uplink,
    ))
    .unwrap();
    let mut amf = NasSecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
    let error = amf.unprotect(&sent, Direction::Uplink).unwrap_err();
    assert_eq!(
        error.to_string(),
        "the message is authentic and is refused: cannot decode: the NAS message container of a \
         ServiceRequest has another message"
    );
    // Its COUNT is used, and the cleartext IEs are read without the context
    assert_eq!(
        amf.nas_count(Direction::Uplink, NasConnection::ThreeGpp),
        NasCount::new(1).ok()
    );
    let Nas5gsMessage::SecurityProtected(_, cleartext) = Nas5gsMessage::decode(&sent).unwrap()
    else {
        panic!()
    };
    assert!(matches!(
        *cleartext,
        Nas5gsMessage::Gmm(_, Nas5gmmMessage::ServiceRequest(_))
    ));

    // In the other direction and under another header a container is what it is
    let downlink = Nas5gsMessage::decode(&[0x7e, 0x00, 0x44, 0x03]).unwrap();
    let mut amf = NasSecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
    let mut ue = NasSecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
    let sent = amf
        .protect(&downlink, integrity_protected, Direction::Downlink)
        .unwrap();
    assert_eq!(ue.unprotect(&sent, Direction::Downlink).unwrap().sent, None);
}

/// The EPS counterpart is the CONTROL PLANE SERVICE REQUEST under "integrity
/// protected and partially ciphered" (TS 24.301 §4.4.5): the context ciphers
/// the value of its ESM message container, and gives it back deciphered.
#[test]
fn an_eps_control_plane_service_request_is_partially_ciphered() {
    let kasme = e::KAsme::new(&[9; 32]);
    let (eia, eea) = (e::IntegrityAlgorithm::EIA2, e::CipheringAlgorithm::EEA2);
    let mut ue = e::NasSecurityContext::from_fresh_kasme(&kasme, eia, eea).unwrap();
    let mut mme = e::NasSecurityContext::from_fresh_kasme(&kasme, eia, eea).unwrap();

    // ESM DATA TRANSPORT of bearer 5 with two octets of user data
    let esm = hex::decode("5200eb0002a1b2").unwrap();
    let request = e::NasControlPlaneServiceRequest::new(
        e::NasControlPlaneServiceType::new(0),
        e::NasKeySetIdentifier::new(0),
    )
    .with_esm_message_container(e::NasEsmMessageContainer::new(esm.clone()));
    let request = e::NasEpsMessage::new_emm(request);
    let partially = e::NasEpsSecurityHeaderType::IntegrityProtectedAndPartiallyCiphered;
    let sent = ue
        .protect(&request, partially, e::Direction::Uplink)
        .unwrap();
    // The header and the cleartext IEs are read without the key, the value is not
    assert_eq!(sent[0], 0x57);
    assert!(!sent.windows(esm.len()).any(|window| window == esm));
    let verified = mme.unprotect(&sent, e::Direction::Uplink).unwrap();
    assert_eq!(verified.message, request);
    assert_eq!(verified.security_header_type, partially);
    let e::NasEpsMessage::Emm(_, e::NasEmmMessage::ControlPlaneServiceRequest(received)) =
        verified.message
    else {
        panic!()
    };
    let container = received.esm_message_container.unwrap();
    assert!(matches!(
        container.decode_as_esm_message().unwrap(),
        e::NasEpsMessage::Esm(_, e::NasEsmMessage::EsmDataTransport(_))
    ));
}
