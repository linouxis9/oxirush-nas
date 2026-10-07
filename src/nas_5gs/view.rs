/*
   OxiRush
   Copyright 2025 - 2026 Valentin D'Emmanuele

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

//! The view of a 5GS message and the values of its IEs.

use crate::common::readable;
use crate::common::view::{self, Ie, Viewed, Visit};
use crate::common::{MessageBody, NasError, Result};
use crate::nas_5gs::messages::{
    Nas5gmmHeader, Nas5gsmHeader, NasPduSessionEstablishmentAccept, NasServiceRequest,
};
use crate::nas_5gs::{
    Nas5gmmMessage, Nas5gmmMessageType, Nas5gsMessage, Nas5gsmMessage, Nas5gsmMessageType,
};

/// Visit the IEs of `body`, with `ie` in the place of the field `field`.
fn with_ie(body: &dyn MessageBody, field: &str, ie: &dyn Ie, visit: &mut Visit<'_>) {
    body.ies(&mut |name, size, other, optional| {
        let ie = if name == field { Some(ie) } else { other };
        visit(name, size, ie, optional)
    });
}

impl Viewed for Nas5gsMessage {
    fn ies(&self, visit: &mut Visit<'_>) {
        match self {
            // The service type shares the octet of the ngKSI (§9.11.3.50).
            Self::Gmm(_, Nas5gmmMessage::ServiceRequest(request)) => {
                with_ie(request, "ngksi", &ServiceTypeAndNgksi(request), visit);
            }
            // The payload container type says what the container carries.
            Self::Gmm(_, Nas5gmmMessage::UlNasTransport(transport))
                if transport.payload_container_type.is_n1_sm() =>
            {
                let container = N1SmContainer(&transport.payload_container);
                with_ie(transport, "payload_container", &container, visit);
            }
            Self::Gmm(_, Nas5gmmMessage::DlNasTransport(transport))
                if transport.payload_container_type.is_n1_sm() =>
            {
                let container = N1SmContainer(&transport.payload_container);
                with_ie(transport, "payload_container", &container, visit);
            }
            Self::Gmm(_, message) => message.body().ies(visit),
            // The selected SSC mode shares the octet of the selected PDU
            // session type (§8.3.2.1).
            Self::Gsm(_, Nas5gsmMessage::PduSessionEstablishmentAccept(accept)) => {
                let selected = SelectedTypeAndSscMode(accept);
                with_ie(accept, "selected_pdu_session_type", &selected, visit);
            }
            Self::Gsm(_, message) => message.body().ies(visit),
            Self::SecurityProtected(_, inner) => inner.ies(visit),
            Self::Opaque(_) => {}
        }
    }

    fn blank(&self, name: &str) -> Option<serde_json::Value> {
        match self {
            Self::Gmm(_, message) => message.body().blank(name),
            Self::Gsm(_, message) => message.body().blank(name),
            Self::SecurityProtected(_, inner) => inner.blank(name),
            Self::Opaque(_) => None,
        }
    }

    const FAMILIES: &'static [&'static str] = &["Gmm", "Gsm"];

    fn prepared(mut self, view: &serde_json::Map<String, serde_json::Value>) -> Self {
        // The payload container is read as its type says.
        let kind = match &mut self {
            Self::Gmm(_, Nas5gmmMessage::UlNasTransport(transport)) => {
                &mut transport.payload_container_type
            }
            Self::Gmm(_, Nas5gmmMessage::DlNasTransport(transport)) => {
                &mut transport.payload_container_type
            }
            _ => return self,
        };
        let written = (view.iter())
            .find(|(name, _)| readable::same_name(name, "payload-container-type"))
            .and_then(|(_, entry)| entry.get("value"));
        if let Some(Ok(written)) = written.map(|value| view::Decoded::with_decoded(kind, value)) {
            *kind = written;
        }
        self
    }
}

impl Nas5gsMessage {
    /// The view of the message: each of its IEs by the name TS 24.501 gives
    /// it, with its `value` and its `octets`.
    ///
    /// `octets` is the value part of the IE in hexadecimal. `value` is what
    /// the typed accessors of the IE decode from it, in the notation a
    /// reader expects: a coded value is its name (`"initial-registration"`)
    /// or, where the specification names none, its number; a PLMN identity
    /// is `"208-93"`; an IMSI, an IMEI or an MSIN is its digits; a TMSI, a
    /// TAC or an SST is a number and a DNN is text; an IP address is its
    /// text; a container of a NAS message is the view of that message.
    /// What has no other notation stays hexadecimal: an SD, a key, a MAC
    /// address. An IE that the crate does not decode, and octets that do
    /// not decode, have `octets` alone.
    ///
    /// Names are in lower case with hyphens; the fields of the header come
    /// first, with a `value` alone, and an optional IE that the message
    /// does not have is `null`. A view is read through a security
    /// header, and the unknown IEs of a message are not in it.
    ///
    /// ```
    /// use oxirush_nas::nas_5gs::Nas5gsMessage;
    /// use serde_json::json;
    ///
    /// // 5GMM STATUS with cause #22.
    /// let status = Nas5gsMessage::from_bytes(&[0x7e, 0x00, 0x64, 0x16]).unwrap();
    /// let mut view = status.to_view();
    /// assert_eq!(view["message-type"]["value"], "5gmm-status");
    /// assert_eq!(view["5gmm-cause"], json!({"value": "congestion", "octets": "16"}));
    ///
    /// view["5gmm-cause"]["value"] = json!("illegal-ue");
    /// let edited = status.with_view(view).unwrap();
    /// assert_eq!(edited.to_bytes().unwrap(), [0x7e, 0x00, 0x64, 0x03]);
    /// ```
    pub fn to_view(&self) -> serde_json::Value {
        view::to_view(self)
    }

    /// The message that an edited view of this one describes.
    ///
    /// An IE whose `value` was changed is encoded from it, and an IE whose
    /// `octets` were changed has those octets, whatever they are: its
    /// length follows. An IE that the view leaves out or has as `null` is
    /// taken out of the message, and an optional IE that the message does
    /// not have is added with the `value` or the `octets` that the view
    /// gives it. The message is otherwise this one, with its unknown IEs.
    ///
    /// A name is read in any case, with hyphens, underscores or spaces, and
    /// a number also as a `"0x…"` string. Nothing that the view says is
    /// ignored: a name that does not exist, a member that an IE or a value
    /// does not have, a value that its IE cannot carry or that the crate
    /// does not encode, and `octets` and a `value` that were both changed
    /// and disagree are errors.
    ///
    /// A value says what an IE means, not how it is coded. The encoder
    /// chooses what the value does not show, such as the unit of a timer
    /// or the type of a partial tracking area identity list; the octets
    /// are the way to choose it. A coded value is written by its name, and
    /// as a number only where it has no name.
    pub fn with_view(&self, view: serde_json::Value) -> Result<Self> {
        view::with_view(self, view).map_err(NasError::EncodingError)
    }
}

impl Nas5gmmMessageType {
    /// The message of this type that a view describes alone.
    ///
    /// The view has every field of the header with its `value`, every
    /// mandatory IE and the optional IEs that the message has, each with
    /// its `value` or its `octets`. It is read as
    /// [`Nas5gsMessage::with_view`] reads one: nothing that it says is
    /// ignored, and a field of the header or a mandatory IE that it leaves
    /// out is an error. A member that a `value` leaves out is zero. The
    /// message in a container is the view that is the `value` of the
    /// container, named by its `message-type`.
    ///
    /// ```
    /// use oxirush_nas::nas_5gs::Nas5gmmMessageType;
    /// use serde_json::json;
    ///
    /// let status = Nas5gmmMessageType::FGmmStatus
    ///     .from_view(json!({
    ///         "extended-protocol-discriminator": {"value": 126},
    ///         "security-header-type": {"value": "plain-nas-message"},
    ///         "message-type": {"value": "5gmm-status"},
    ///         "5gmm-cause": {"value": "congestion"},
    ///     }))
    ///     .unwrap();
    /// assert_eq!(status.to_bytes().unwrap(), [0x7e, 0x00, 0x64, 0x16]);
    /// ```
    pub fn from_view(self, view: serde_json::Value) -> Result<Nas5gsMessage> {
        view::from_view(&["Gmm"], &format!("{self:?}"), view).map_err(NasError::EncodingError)
    }

    /// The names of the entries that the view of a message of this type
    /// has: the fields of its header, then its IEs in the order of the
    /// message, with those that are optional. A type that the crate has no
    /// message of has none.
    pub fn view_names(self) -> Vec<String> {
        view::names::<Nas5gmmHeader, Nas5gmmMessage>(&[&format!("{self:?}")])
    }
}

impl Nas5gsmMessageType {
    /// The message of this type that a view describes alone, as
    /// [`Nas5gmmMessageType::from_view`] has it.
    pub fn from_view(self, view: serde_json::Value) -> Result<Nas5gsMessage> {
        view::from_view(&["Gsm"], &format!("{self:?}"), view).map_err(NasError::EncodingError)
    }

    /// The names of the entries that the view of a message of this type
    /// has: the fields of its header, then its IEs in the order of the
    /// message, with those that are optional. A type that the crate has no
    /// message of has none.
    pub fn view_names(self) -> Vec<String> {
        view::names::<Nas5gsmHeader, Nas5gsmMessage>(&[&format!("{self:?}")])
    }
}

// ── Values ─────────────────────────────────────────────────────────────────
//
// Each is what the typed accessors of the IE return, and is encoded back
// by the matching constructor or setters.

use crate::common::ts24301::KeySetIdentifier;
use crate::common::view::{
    Code, built_ie, code_ie, container_ie, decoded_ie, fields_ie, listed_ie, named_ie, numbers,
    octets, shared_ies, timer_ie,
};
use crate::common::{decode_labels, encode_labels};
use crate::nas_5gs::ie::*;
use crate::nas_5gs::types::*;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

// The IEs that TS 24.501 and TS 24.301 have alike.
shared_ies!();

/// The service type and the ngKSI in the first octet of a SERVICE REQUEST:
/// the message has the accessors of the service type.
struct ServiceTypeAndNgksi<'a>(&'a NasServiceRequest);

#[derive(Serialize, Deserialize)]
struct ServiceTypeAndKeySetIdentifier {
    service_type: Code<ServiceType>,
    key_set_identifier: KeySetIdentifier,
}

impl ServiceTypeAndNgksi<'_> {
    fn of(request: &NasServiceRequest) -> ServiceTypeAndKeySetIdentifier {
        let service_type = request.service_type_raw();
        ServiceTypeAndKeySetIdentifier {
            service_type: Code::of(ServiceType::from_u8_strict(service_type), service_type),
            key_set_identifier: request.ngksi.key_set_identifier(),
        }
    }
}

impl Ie for ServiceTypeAndNgksi<'_> {
    fn value(&self) -> Option<serde_json::Value> {
        readable::to_value(&Self::of(self.0)).ok()
    }

    fn encoded(
        &self,
        value: &serde_json::Value,
    ) -> std::result::Result<(serde_json::Value, Option<serde_json::Value>), String> {
        let octet: ServiceTypeAndKeySetIdentifier = readable::from_value(value)?;
        let written = readable::to_value(&octet)?;
        let mut request = self.0.clone();
        if let Code::Name(name) = octet.service_type {
            request.set_service_type(name);
        }
        (request.ngksi)
            .set_key_set_identifier(octet.key_set_identifier)
            .map_err(|error| error.to_string())?;
        let now = readable::to_value(&Self::of(&request))?;
        if now != written {
            return Err(format!(
                "{written} cannot be encoded: the IE would be {now}"
            ));
        }
        Ok((readable::to_value(&request.ngksi)?, Some(now)))
    }
}

/// The selected PDU session type and the selected SSC mode in the first
/// octet of a PDU SESSION ESTABLISHMENT ACCEPT: the message has the accessors
/// of the SSC mode.
struct SelectedTypeAndSscMode<'a>(&'a NasPduSessionEstablishmentAccept);

#[derive(Serialize, Deserialize)]
struct SessionTypeAndSscMode {
    pdu_session_type: Code<PduSessionTypeValue>,
    ssc_mode: Code<SscModeValue>,
}

impl SelectedTypeAndSscMode<'_> {
    fn of(accept: &NasPduSessionEstablishmentAccept) -> SessionTypeAndSscMode {
        let (kind, mode) = (accept.pdu_session_type(), accept.selected_ssc_mode());
        SessionTypeAndSscMode {
            pdu_session_type: Code::of(accept.selected_pdu_session_type_value(), kind),
            ssc_mode: Code::of(accept.selected_ssc_mode_value(), mode),
        }
    }
}

impl Ie for SelectedTypeAndSscMode<'_> {
    fn value(&self) -> Option<serde_json::Value> {
        readable::to_value(&Self::of(self.0)).ok()
    }

    fn encoded(
        &self,
        value: &serde_json::Value,
    ) -> std::result::Result<(serde_json::Value, Option<serde_json::Value>), String> {
        let octet: SessionTypeAndSscMode = readable::from_value(value)?;
        let written = readable::to_value(&octet)?;
        let mut accept = self.0.clone();
        match octet.pdu_session_type {
            Code::Name(name) => accept.set_selected_pdu_session_type(name),
            Code::Number(number) => accept.selected_pdu_session_type.value = number,
        }
        match octet.ssc_mode {
            Code::Name(name) => accept.set_selected_ssc_mode(name),
            Code::Number(number) => accept.selected_pdu_session_type.type_field = number,
        }
        let now = readable::to_value(&Self::of(&accept))?;
        if now != written {
            return Err(format!(
                "{written} cannot be encoded: the IE would be {now}"
            ));
        }
        Ok((
            readable::to_value(&accept.selected_pdu_session_type)?,
            Some(now),
        ))
    }
}

/// A payload container of the type "N1 SM information": a 5GSM message.
struct N1SmContainer<'a>(&'a NasPayloadContainer);

impl N1SmContainer<'_> {
    fn message(&self) -> Option<Nas5gsMessage> {
        let message = self.0.decode_as_n1_sm_message().ok()?;
        matches!(message, Nas5gsMessage::Gsm(..)).then_some(message)
    }
}

impl Ie for N1SmContainer<'_> {
    fn value(&self) -> Option<serde_json::Value> {
        Some(view::to_view(&self.message()?))
    }

    fn encoded(
        &self,
        value: &serde_json::Value,
    ) -> std::result::Result<(serde_json::Value, Option<serde_json::Value>), String> {
        let message = match self.message() {
            Some(message) => view::with_view(&message, value.clone())?,
            // A container without octets carries what the view names.
            None if self.0.value.is_empty() => view::contained(value)?,
            None => return Err("the octets are not a 5GSM message: write them".into()),
        };
        let container =
            NasPayloadContainer::from_n1_sm_message(&message).map_err(|error| error.to_string())?;
        Ok((
            readable::to_value(&container)?,
            Some(view::to_view(&message)),
        ))
    }
}

// A container of a plain NAS message: the view of the message.
container_ie!(
    NasMessageContainer: Nas5gsMessage,
    |ie| (ie.decode_plain_inner().ok())
        .filter(|message| matches!(message, Nas5gsMessage::Gmm(..))),
    |message| NasMessageContainer::from_plain_message(message).ok()
);
container_ie!(
    NasEpsNasMessageContainer: crate::nas_eps::NasEpsMessage,
    |ie| ie.decode_as_eps_message().ok(),
    |message| NasEpsNasMessageContainer::from_eps_message(message).ok()
);

// One coded value.
code_ie!(
    NasFGmmCause,
    GmmCause,
    |ie| ie.cause(),
    NasFGmmCause::from_cause
);
code_ie!(
    NasFGsmCause,
    GsmCause,
    |ie| ie.cause(),
    NasFGsmCause::from_cause
);
code_ie!(
    NasFGsIdentityType,
    MobileIdentityType,
    |ie| ie.identity_type_strict(),
    NasFGsIdentityType::from_identity_type
);
code_ie!(
    NasPduSessionType,
    PduSessionTypeValue,
    |ie| ie.session_type(),
    NasPduSessionType::from_session_type
);
code_ie!(
    NasSscMode,
    SscModeValue,
    |ie| ie.mode(),
    NasSscMode::from_mode
);
code_ie!(
    NasAccessType,
    AccessTypeValue,
    |ie| ie.access_type(),
    NasAccessType::from_access_type
);
code_ie!(
    NasPayloadContainerType,
    PayloadContainerKind,
    |ie| ie.kind(),
    NasPayloadContainerType::from_kind
);
code_ie!(
    NasNssaiInclusionMode,
    NssaiInclusionModeValue,
    |ie| Some(ie.mode()),
    NasNssaiInclusionMode::from_mode
);
code_ie!(
    NasMaPduSessionInformation,
    MaPduSessionInfoValue,
    |ie| ie.info(),
    NasMaPduSessionInformation::from_info
);
code_ie!(
    NasProseRelayTransactionIdentity,
    ProseRelayTransactionIdentityValue,
    |ie| ie.identity(),
    NasProseRelayTransactionIdentity::from_identity
);
named_ie!(
    NasFGsDrxParameters,
    DrxValue,
    |ie| ie.drx_value(),
    NasFGsDrxParameters::from_drx_value
);
named_ie!(
    NasNbN1ModeDrxParameters,
    NbN1DrxValue,
    |ie| ie.drx_value(),
    NasNbN1ModeDrxParameters::from_drx_value
);
named_ie!(NasRsn, RsnValue, |ie| ie.rsn(), NasRsn::from_rsn);
named_ie!(
    NasFGsAdditionalRequestResult,
    PagingRestrictionDecision,
    |ie| ie.prd(),
    NasFGsAdditionalRequestResult::from_prd
);
named_ie!(
    NasDaylightSavingTime,
    DaylightSavingAdjustment,
    |ie| ie.adjustment(),
    NasDaylightSavingTime::from_adjustment
);
named_ie!(
    NasWusAssistanceInformation,
    UePagingProbability,
    |ie| ie.paging_probability(),
    NasWusAssistanceInformation::from_paging_probability
);
named_ie!(
    NasEthernetHeaderCompressionConfiguration,
    EthHdrCompCidLen,
    |ie| ie.cid_length(),
    NasEthernetHeaderCompressionConfiguration::from_cid_length
);

// The fields of an octet.
fields_ie!(NasFGsRegistrationType {
    "registration-type":
        |ie| Code::of(RegistrationType::from_u8_strict(ie.value & 0x07), ie.value & 0x07),
        |ie, code: Code<RegistrationType>| if let Code::Name(name) = code {
            ie.set_registration_type(name)
        };
    "follow-on-request": |ie| ie.follow_on_request(), |ie, on: bool| ie.set_follow_on_request(on);
    "ngksi": |ie| ie.ngksi(), |ie, ngksi: u8| ie.set_ngksi(ngksi);
    "tsc": |ie| ie.tsc(), |ie, tsc: bool| ie.set_tsc(tsc);
});
fields_ie!(NasDeRegistrationType {
    "switch-off": |ie| ie.switch_off(), |ie, on: bool| ie.set_switch_off(on);
    "re-registration-required":
        |ie| ie.re_registration_required(),
        |ie, on: bool| ie.set_re_registration_required(on);
    "access-type":
        |ie| Code::of(ie.deregistration_access_type(), ie.access_type_raw()),
        |ie, code: Code<DeregistrationAccessType>| if let Code::Name(name) = code {
            ie.set_deregistration_access_type(name)
        };
    "ngksi": |ie| ie.ngksi(), |ie, ngksi: u8| ie.set_ngksi(ngksi);
    "tsc": |ie| ie.tsc(), |ie, tsc: bool| ie.set_tsc(tsc);
});
fields_ie!(NasFGsUpdateType {
    "sms-requested": |ie| ie.sms_requested(), |ie, on: bool| ie.set_sms_requested(on);
    "ng-ran-rcu": |ie| ie.ng_ran_rcu(), |ie, on: bool| ie.set_ng_ran_rcu(on);
    "pnb-ciot": |ie| ie.pnb_ciot(), |ie, value: u8| ie.set_pnb_ciot(value);
    "eps-pnb-ciot": |ie| ie.eps_pnb_ciot(), |ie, value: u8| ie.set_eps_pnb_ciot(value);
});
fields_ie!(NasFGsRegistrationResult {
    "result":
        |ie| Code::of(
            RegistrationResult::from_u8_strict(ie.result_value_raw()),
            ie.result_value_raw(),
        ),
        |ie, code: Code<RegistrationResult>| if let Code::Name(name) = code {
            ie.set_result_value(name)
        };
    "sms-allowed": |ie| ie.sms_allowed(), |ie, on: bool| ie.set_sms_allowed(on);
    "nssaa-performed": |ie| ie.nssaa_performed(), |ie, on: bool| ie.set_nssaa_performed(on);
    "emergency-registered":
        |ie| ie.emergency_registered(),
        |ie, on: bool| ie.set_emergency_registered(on);
    "disaster-roaming": |ie| ie.disaster_roaming(), |ie, on: bool| ie.set_disaster_roaming(on);
});
fields_ie!(NasControlPlaneServiceType {
    "service-type":
        |ie| Code::of(
            ControlPlaneServiceTypeValue::from_u8_strict(ie.service_type_raw()),
            ie.service_type_raw(),
        ),
        |ie, code: Code<ControlPlaneServiceTypeValue>| if let Code::Name(name) = code {
            ie.set_service_type(name)
        };
    "ngksi": |ie| ie.ngksi(), |ie, ngksi: u8| ie.set_ngksi(ngksi);
    "tsc": |ie| ie.tsc(), |ie, tsc: bool| ie.set_tsc(tsc);
});
fields_ie!(NasSecurityAlgorithms {
    "ciphering":
        |ie| Code::of(ie.ciphering(), ie.ciphering_raw()),
        |ie, code: Code<CipheringAlgorithm>| if let Code::Name(name) = code {
            ie.set_ciphering(name)
        };
    "integrity":
        |ie| Code::of(ie.integrity(), ie.integrity_raw()),
        |ie, code: Code<IntegrityAlgorithm>| if let Code::Name(name) = code {
            ie.set_integrity(name)
        };
});
fields_ie!(NasEpsNasSecurityAlgorithms {
    "ciphering":
        |ie| Code::of(ie.ciphering(), ie.ciphering_raw()),
        |ie, code: Code<crate::common::ts24301::CipheringAlgorithm>| {
            if let Code::Name(name) = code {
                ie.set_ciphering(name)
            }
        };
    "integrity":
        |ie| Code::of(ie.integrity(), ie.integrity_raw()),
        |ie, code: Code<crate::common::ts24301::IntegrityAlgorithm>| {
            if let Code::Name(name) = code {
                ie.set_integrity(name)
            }
        };
});
fields_ie!(NasTimeZoneAndTime {
    "year": |ie| ie.year(), |ie, year: u8| {
        ie.set_year(year);
    };
    "month": |ie| ie.month(), |ie, month: u8| {
        ie.set_month(month);
    };
    "day": |ie| ie.day(), |ie, day: u8| {
        ie.set_day(day);
    };
    "hour": |ie| ie.hour(), |ie, hour: u8| {
        ie.set_hour(hour);
    };
    "minute": |ie| ie.minute(), |ie, minute: u8| {
        ie.set_minute(minute);
    };
    "second": |ie| ie.second(), |ie, second: u8| {
        ie.set_second(second);
    };
    "time-zone-quarter-hours": |ie| ie.timezone_quarter_hours(), |ie, quarters: i8| {
        ie.set_timezone_quarter_hours(quarters);
    };
});

// The flags of an indication, by the names of its accessors.
built_ie!(
    NasAdditional5gSecurityInformation,
    |rinmr, hdp| Some(Self::from_flags(rinmr, hdp)),
    { rinmr: bool, hdp: bool }
);
built_ie!(
    NasAdditionalConfigurationIndication,
    |scmr| Some(Self::from_scmr(scmr)),
    { scmr: bool }
);
built_ie!(
    NasAdditionalInformationRequested,
    |requested| Some(Self::from_cipher_key_data_requested(requested)),
    { cipher_key_data_requested: bool }
);
built_ie!(
    NasAllowedSscMode,
    |ssc1, ssc2, ssc3| Some(Self::from_modes(ssc1, ssc2, ssc3)),
    { ssc1: bool, ssc2: bool, ssc3: bool }
);
built_ie!(NasAlwaysOnPduSessionIndication, |apsi| Some(Self::from_apsi(apsi)), { apsi: bool });
built_ie!(NasAlwaysOnPduSessionRequested, |apsr| Some(Self::from_apsr(apsr)), { apsr: bool });
built_ie!(NasAun3Indication, |aun3reg| Some(Self::from_aun3reg(aun3reg)), { aun3reg: bool });
built_ie!(
    NasConfigurationUpdateIndication,
    |ack, red| Some(Self::from_flags(ack, red)),
    { ack: bool, red: bool }
);
built_ie!(NasControlPlaneOnlyIndication, Self::try_from_cpoi, { cpoi: bool });
built_ie!(
    NasExtendedFGmmCause,
    |not_allowed| Some(Self::from_satellite_nr_not_allowed(not_allowed)),
    { satellite_nr_not_allowed: bool }
);
built_ie!(
    NasFGsmCongestionReAttemptIndicator,
    |abo, catbo| Some(Self::from_flags(abo, catbo)),
    { abo: bool, catbo: bool }
);
built_ie!(
    NasFGsmNetworkFeatureSupport,
    |ept_s1, naps| Some(Self::from_flags(ept_s1, naps)),
    { ept_s1: bool, naps: bool }
);
built_ie!(
    NasFeatureAuthorizationIndication,
    |hpase, mbsrai| Some(Self::from_flags(hpase, mbsrai)),
    { hpase: bool, mbsrai: FeatureAuthMbsraiValue = |ie| ie.mbsrai() }
);
built_ie!(NasLpWusStatus, |disabled| Some(Self::from_disabled(disabled)), {
    lp_wus_disabled: bool
});
built_ie!(
    NasMicoIndication,
    |raai, sprti| Some(Self::from_flags(raai, sprti)),
    { raai: bool, sprti: bool }
);
built_ie!(NasN5gcIndication, |n5gc| Some(Self::from_n5gc(n5gc)), { n5gc: bool });
built_ie!(
    NasNetworkSlicingIndication,
    |nssci, dcni| Some(Self::from_flags(nssci, dcni)),
    { nssci: bool, dcni: bool }
);
built_ie!(
    NasNon3GppAccessPathSwitchingIndication,
    |naps| Some(Self::from_naps(naps)),
    { naps: bool }
);
built_ie!(
    NasNon3GppPathSwitchingInformation,
    |nsonr| Some(Self::from_nsonr(nsonr)),
    { nsonr: bool }
);
built_ie!(NasPayloadContainerInformation, |pru| Some(Self::from_pru(pru)), { pru: bool });
built_ie!(
    NasPriorityIndicator,
    |mpsi, mcsi| Some(Self::from_flags(mpsi, mcsi)),
    { mpsi: bool, mcsi: bool }
);
built_ie!(
    NasRanTimingSynchronization,
    |request| Some(Self::from_recreation_request(request)),
    { recreation_request: bool }
);
built_ie!(NasSmsIndication, |sai| Some(Self::from_sai(sai)), { sai: bool });
built_ie!(
    NasUeUsageSetting,
    |data_centric| Some(Self::from_data_centric(data_centric)),
    { data_centric: bool }
);
built_ie!(NasTruncatedFGSTmsiConfiguration, Self::try_from_lengths, {
    truncated_amf_set_id_length: u8 = |ie| ie.truncated_amf_set_id_length(),
    truncated_amf_pointer_length: u8 = |ie| ie.truncated_amf_pointer_length(),
});
built_ie!(NasRegistrationWaitRange, Self::from_range, {
    min_seconds: u64 = |ie| ie.min_seconds(),
    max_seconds: u64 = |ie| ie.max_seconds(),
});
built_ie!(
    NasAun3DeviceSecurityKey,
    |askt, key: Vec<u8>| Self::try_from_typed(askt, &key).ok(),
    {
        askt: Aun3DeviceSecurityKeyType = |ie| ie.askt(),
        key: Vec<u8> = |ie| ie.key().map(<[u8]>::to_vec),
    }
);

// The parts of an IE that its constructor takes.
built_ie!(
    NasIpHeaderCompressionConfiguration,
    |profiles, max_cid, setup: Option<IpHdrCompAdditionalSetupType>, container: Option<Vec<u8>>| {
        match (setup, container) {
            (None, None) => Self::from_profiles(profiles, max_cid),
            (Some(setup), container) => Self::from_profiles_with_additional_setup(
                profiles,
                max_cid,
                setup,
                &container.unwrap_or_default(),
            ),
            (None, Some(_)) => None,
        }
    },
    {
        profiles: IpHdrCompProfiles = |ie| ie.is_well_formed().then(|| ie.profiles()),
        max_cid: u16,
        additional_setup_type: Option<IpHdrCompAdditionalSetupType> =
            |ie| Some(ie.additional_setup_type_value()),
        additional_setup_container: Option<Vec<u8>> =
            |ie| Some(ie.additional_setup_container().map(<[u8]>::to_vec)),
    }
);
built_ie!(
    NasPagingRestriction,
    |restriction_type, psis: Vec<u16>| Some(Self::from_restriction_type_with_unrestricted_psis(
        restriction_type,
        &octets(&psis)?
    )),
    {
        restriction_type: PagingRestrictionType =
            |ie| ie.restriction_type().filter(|_| ie.is_well_formed()),
        unrestricted_psi_list: Vec<u16> = |ie| Some(numbers(&ie.unrestricted_psi_list())),
    }
);
built_ie!(
    NasTnanInformation,
    |tngf_id: Option<Vec<u8>>, ssid: Option<String>| {
        let fits = tngf_id.as_ref().is_none_or(|id| id.len() <= 255)
            && ssid.as_ref().is_none_or(|ssid| ssid.len() <= 32);
        let ie = Self::new(Vec::new()).with_tngf_id(tngf_id.as_deref().filter(|_| fits));
        fits.then(|| ie.with_ssid(ssid.as_ref().map(String::as_bytes)))
    },
    {
        tngf_id: Option<Vec<u8>> = |ie| match ie.tngf_id_indicator() {
            true => Some(Some(ie.tngf_id()?.to_vec())),
            false => Some(None),
        },
        ssid: Option<String> = |ie| match ie.ssid_indicator() {
            true => String::from_utf8(ie.ssid()?.to_vec()).ok().map(Some),
            false => Some(None),
        },
    }
);

/// What an LP-WUS PS assistance information is, by its type.
#[derive(Serialize, Deserialize)]
enum LpWuspsAssistance {
    PagingSubgroupId(u8),
    UePagingProbabilityInformation(u8),
}

decoded_ie!(
    NasLpWuspsAssistanceInformation: LpWuspsAssistance,
    |ie| (ie.paging_subgroup_id().map(LpWuspsAssistance::PagingSubgroupId)).or_else(|| {
        let information = ie.ue_paging_probability_information();
        information.map(LpWuspsAssistance::UePagingProbabilityInformation)
    }),
    |_, assistance| match assistance {
        LpWuspsAssistance::PagingSubgroupId(id) => Self::try_from_paging_subgroup_id(id).ok(),
        LpWuspsAssistance::UePagingProbabilityInformation(information) => {
            Self::try_from_ue_paging_probability_information(information).ok()
        }
    }
);
// The correctionField of IEEE Std 1588: a number of 2^-16 ns.
decoded_ie!(
    NasUeDsTtResidenceTime: i64,
    |ie| {
        let field = ie.correction_field().filter(|_| ie.is_well_formed())?;
        Some(i64::from_le_bytes(field.wire_bytes()))
    },
    |_, field| {
        let field = DsTtCorrectionField::from_wire_bytes(field.to_le_bytes());
        Some(Self::from_correction_field(field))
    }
);

/// The identity of a 5GS mobile identity, by its type of identity.
#[derive(Serialize, Deserialize)]
enum MobileIdentity {
    NoIdentity,
    Suci(SuciForm),
    Guti(Guti),
    Imei(String),
    STmsi(STmsi),
    Imeisv(String),
    MacAddress { address: [u8; 6], mauri: bool },
    Eui64([u8; 8]),
}

/// A SUCI with its digits: the MSIN of the null scheme, else the output of
/// the protection scheme.
#[derive(Serialize, Deserialize)]
enum SuciForm {
    Imsi {
        plmn: PlmnId,
        routing_indicator: String,
        protection_scheme: ProtectionScheme,
        home_network_public_key_id: u8,
        msin: Option<String>,
        scheme_output: Option<Vec<u8>>,
    },
    Nai {
        supi_format: SupiFormat,
        nai: String,
    },
}

/// Digits as `octets` of BCD, the first in the low half, filled with 1111.
fn bcd(digits: &str, octets: usize) -> Option<Vec<u8>> {
    let digit = |at: usize| match digits.as_bytes().get(at) {
        Some(digit) if digit.is_ascii_digit() => Some(digit - b'0'),
        Some(_) => None,
        None => Some(0x0f),
    };
    (digits.len() <= 2 * octets)
        .then(|| (0..octets).map(|at| Some(digit(2 * at + 1)? << 4 | digit(2 * at)?)))?
        .collect()
}

impl SuciForm {
    fn of(suci: Suci) -> Self {
        match suci {
            Suci::Utf8 { supi_format, nai } => Self::Nai { supi_format, nai },
            Suci::Imsi(suci) => {
                let null = suci.protection_scheme == ProtectionScheme::Null;
                Self::Imsi {
                    plmn: suci.plmn_id,
                    routing_indicator: bcd_to_string(&suci.routing_indicator),
                    protection_scheme: suci.protection_scheme,
                    home_network_public_key_id: suci.home_nw_public_key_id,
                    msin: null.then(|| bcd_to_string(&suci.scheme_output)),
                    scheme_output: (!null).then_some(suci.scheme_output),
                }
            }
        }
    }

    fn suci(self) -> Option<Suci> {
        Some(match self {
            Self::Nai { supi_format, nai } => Suci::Utf8 { supi_format, nai },
            Self::Imsi {
                plmn,
                routing_indicator,
                protection_scheme,
                home_network_public_key_id,
                msin,
                scheme_output,
            } => Suci::Imsi(ImsiSuci {
                plmn_id: plmn,
                routing_indicator: bcd(&routing_indicator, 2)?,
                protection_scheme,
                home_nw_public_key_id: home_network_public_key_id,
                scheme_output: match (msin, scheme_output) {
                    (Some(msin), None) => bcd(&msin, msin.len().div_ceil(2))?,
                    (None, Some(output)) => output,
                    _ => return None,
                },
            }),
        })
    }
}

decoded_ie!(
    NasFGsMobileIdentity: MobileIdentity,
    |ie| Some(match ie.identity_type()? {
        MobileIdentityType::NoIdentity => MobileIdentity::NoIdentity,
        MobileIdentityType::Suci => MobileIdentity::Suci(SuciForm::of(ie.as_suci()?)),
        MobileIdentityType::Guti => MobileIdentity::Guti(ie.as_guti()?),
        MobileIdentityType::Imei => MobileIdentity::Imei(ie.as_imei()?),
        MobileIdentityType::STmsi => MobileIdentity::STmsi(ie.as_s_tmsi()?),
        MobileIdentityType::Imeisv => MobileIdentity::Imeisv(ie.as_imeisv()?),
        MobileIdentityType::MacAddr => MobileIdentity::MacAddress {
            address: ie.as_mac_address()?,
            mauri: ie.mauri()?,
        },
        MobileIdentityType::Eui64 => MobileIdentity::Eui64(ie.as_eui64()?),
    }),
    |_, identity| match identity {
        MobileIdentity::NoIdentity => Some(NasFGsMobileIdentity::from_no_identity()),
        MobileIdentity::Suci(suci) => NasFGsMobileIdentity::try_from_suci(&suci.suci()?),
        MobileIdentity::Guti(guti) => NasFGsMobileIdentity::try_from_guti(&guti),
        MobileIdentity::Imei(imei) => NasFGsMobileIdentity::try_from_imei(&imei),
        MobileIdentity::STmsi(s_tmsi) => NasFGsMobileIdentity::try_from_s_tmsi(&s_tmsi),
        MobileIdentity::Imeisv(imeisv) => NasFGsMobileIdentity::try_from_imeisv(&imeisv),
        MobileIdentity::MacAddress { address, mauri } => {
            Some(NasFGsMobileIdentity::from_mac_address_with_mauri(address, mauri))
        }
        MobileIdentity::Eui64(eui64) => Some(NasFGsMobileIdentity::from_eui64(eui64)),
    }
);
decoded_ie!(
    NasDsTtEthernetPortMacAddress: [u8; 6],
    |ie| ie.mac_address(),
    |_, address| Some(NasDsTtEthernetPortMacAddress::from_mac_address(address))
);

/// The algorithms a UE security capability has the bits of, by number.
#[derive(Serialize, Deserialize)]
struct SecurityCapability {
    ea: Vec<u16>,
    ia: Vec<u16>,
    eea: Option<Vec<u16>>,
    eia: Option<Vec<u16>>,
}

/// The algorithms an octet of a capability has the bits of, by number.
fn supported<T>(ie: &T, supports: fn(&T, u8) -> bool) -> Vec<u16> {
    (0..8)
        .filter(|algorithm| supports(ie, *algorithm))
        .map(u16::from)
        .collect()
}

/// The octet of a capability with the bits of `algorithms`, 0 in bit 8.
fn algorithm_bits(algorithms: &[u16]) -> Option<u8> {
    algorithms.iter().try_fold(0, |bits, algorithm| {
        Some(bits | 0x80u8.checked_shr((*algorithm).into())?)
    })
}

decoded_ie!(
    NasUeSecurityCapability: SecurityCapability,
    |ie| {
        let eps = ie.has_eps_algorithms();
        Some(SecurityCapability {
            ea: supported(ie, Self::supports_ea),
            ia: supported(ie, Self::supports_ia),
            eea: eps.then(|| supported(ie, Self::supports_eea)),
            eia: eps.then(|| supported(ie, Self::supports_eia)),
        })
    },
    |_, capability| {
        let (ea, ia) = (algorithm_bits(&capability.ea)?, algorithm_bits(&capability.ia)?);
        Some(match (capability.eea, capability.eia) {
            (None, None) => NasUeSecurityCapability::from_capabilities(ea, ia),
            (eea, eia) => NasUeSecurityCapability::from_capabilities_extended(
                ea,
                ia,
                algorithm_bits(&eea.unwrap_or_default())?,
                algorithm_bits(&eia.unwrap_or_default())?,
            ),
        })
    }
);

// Slices, tracking areas and PLMNs.
decoded_ie!(NasSNssai: SNssaiContents, |ie| ie.parse(), |_, contents| contents.to_snssai());
decoded_ie!(
    NasNssai: Vec<SNssaiContents>,
    |ie| ie.try_parse_all(),
    |_, contents| {
        let snssais: Option<Vec<_>> = contents.iter().map(SNssaiContents::to_snssai).collect();
        NasNssai::try_from_snssais(&snssais?)
    }
);
decoded_ie!(
    NasMappedNssai: Vec<SNssaiContents>,
    |ie| ie.try_parse_all(),
    |_, contents| {
        let snssais: Option<Vec<_>> = contents.iter().map(SNssaiContents::to_snssai).collect();
        NasMappedNssai::from_snssais(&snssais?)
    }
);

/// A rejected S-NSSAI and the cause of its rejection.
#[derive(Serialize, Deserialize)]
struct RejectedSNssai {
    cause: RejectedNssaiCause,
    s_nssai: SNssaiContents,
}

decoded_ie!(
    NasRejectedNssai: Vec<RejectedSNssai>,
    |ie| ie.receiver_syntax_is_valid().then(|| {
        (ie.entries().into_iter())
            .map(|(cause, s_nssai)| RejectedSNssai { cause, s_nssai })
            .collect()
    }),
    |_, rejected| {
        let snssais: Option<Vec<_>> = rejected.iter().map(|one| one.s_nssai.to_snssai()).collect();
        let snssais = snssais?;
        let entries: Vec<_> = rejected.iter().map(|one| one.cause).zip(&snssais).collect();
        NasRejectedNssai::from_entries(&entries)
    }
);
decoded_ie!(
    NasFGsTrackingAreaIdentity: TrackingAreaIdentity,
    |ie| ie.parse(),
    |_, tai| NasFGsTrackingAreaIdentity::try_from_plmn_tac(&tai.plmn, tai.tac)
);
decoded_ie!(
    NasFGsTrackingAreaIdentityList: Vec<TaiListEntry>,
    |ie| ie.receiver_syntax_is_valid().then(|| ie.parse()),
    |_, entries| NasFGsTrackingAreaIdentityList::try_from_entries(&entries)
);
decoded_ie!(
    NasPlmnList: Vec<PlmnId>,
    |ie| ie.is_well_formed().then(|| ie.plmns()),
    |_, plmns| NasPlmnList::from_plmns(&plmns)
);
decoded_ie!(
    NasPlmnIdentity: PlmnId,
    |ie| ie.plmn(),
    |_, plmn| Some(NasPlmnIdentity::from_plmn(&plmn))
);
decoded_ie!(
    NasLadnIndication: Vec<String>,
    |ie| ie.dnn_values().iter().map(|dnn| decode_labels(dnn)).collect(),
    |_, dnns| {
        let dnns: Option<Vec<_>> = dnns.iter().map(|dnn| encode_labels(dnn, 100)).collect();
        NasLadnIndication::from_dnn_values(&dnns?)
    }
);

// Timers, names and numbers.
timer_ie!(NasGprsTimer, NasGprsTimer2, NasGprsTimer3);
decoded_ie!(NasDnn: String, |ie| ie.as_string(), |_, name| NasDnn::from_string(&name));
decoded_ie!(NasNid: String, |ie| Some(ie.nid_value()), |_, nid| NasNid::from_nid_value(&nid));
decoded_ie!(
    NasSmPduDnRequestContainer: String,
    |ie| ie.as_utf8_str().map(str::to_string),
    |_, text| Some(NasSmPduDnRequestContainer::from_str(&text))
);

decoded_ie!(
    NasTimeZone: i8,
    |ie| ie.is_well_formed().then(|| ie.quarter_hours()),
    |_, quarter_hours| NasTimeZone::from_quarter_hours(quarter_hours)
);
decoded_ie!(
    NasPduSessionIdentity2: u8,
    |ie| Some(ie.pdu_session_id()),
    |_, identity| Some(NasPduSessionIdentity2::from_pdu_session_id(identity))
);
decoded_ie!(
    NasPduSessionPairId: u8,
    |ie| ie.pair_id(),
    |_, identity| Some(NasPduSessionPairId::from_pair_id(identity))
);
decoded_ie!(
    NasMaximumNumberOfSupportedPacketFilters: u16,
    |ie| ie.is_well_formed().then(|| ie.max_filters()),
    |_, filters| NasMaximumNumberOfSupportedPacketFilters::try_from_max_filters(filters)
);
decoded_ie!(
    NasN1ModeToS1ModeNasTransparentContainer: u8,
    |ie| Some(ie.sequence_number()),
    |_, number| Some(NasN1ModeToS1ModeNasTransparentContainer::from_sequence_number(number))
);
decoded_ie!(
    NasTimeDuration: u32,
    |ie| ie.seconds(),
    |_, seconds| NasTimeDuration::from_seconds(seconds)
);
decoded_ie!(
    NasEcnMarkingL4sIndication: Vec<u16>,
    |ie| Some(numbers(ie.qri_values())),
    |_, qris| NasEcnMarkingL4sIndication::try_from_qri_values(&octets(&qris)?).ok()
);
decoded_ie!(
    NasSupportedCodecList: Vec<(u8, Vec<u8>)>,
    |ie| ie.codec_bitmaps(),
    |_, bitmaps| NasSupportedCodecList::from_codec_bitmaps(&bitmaps)
);

// Sessions: the identities a status has the bits of, and what a session has.
decoded_ie!(
    NasPduSessionStatus: Vec<u16>,
    |ie| Some(numbers(&ie.active_sessions())),
    |_, sessions| Some(NasPduSessionStatus::from_sessions(&octets(&sessions)?))
);
decoded_ie!(
    NasUplinkDataStatus: Vec<u16>,
    |ie| Some(numbers(&ie.sessions_with_data())),
    |_, sessions| Some(NasUplinkDataStatus::from_sessions(&octets(&sessions)?))
);
decoded_ie!(
    NasAllowedPduSessionStatus: Vec<u16>,
    |ie| Some(numbers(&ie.allowed_sessions())),
    |_, sessions| Some(NasAllowedPduSessionStatus::from_sessions(&octets(&sessions)?))
);
decoded_ie!(
    NasPduSessionReactivationResult: Vec<u16>,
    |ie| Some(numbers(&ie.failed_sessions())),
    |_, sessions| Some(NasPduSessionReactivationResult::from_failed_sessions(&octets(
        &sessions
    )?))
);
decoded_ie!(
    NasSessionAmbr: SessionAmbrValue,
    |ie| ie.parse(),
    |_, ambr| NasSessionAmbr::try_from_kbps(ambr.dl_kbps, ambr.ul_kbps)
);

/// The addresses of a PDU address, by the PDU session type that has them.
#[derive(Serialize, Deserialize)]
struct PduAddress {
    ipv4: Option<Ipv4Addr>,
    ipv6_interface_id: Option<[u8; 8]>,
    smf_ipv6_link_local_address: Option<Ipv6Addr>,
}

decoded_ie!(
    NasPduAddress: PduAddress,
    |ie| ie.receiver_syntax_is_valid().then(|| PduAddress {
        ipv4: ie.ipv4().map(Ipv4Addr::from),
        ipv6_interface_id: ie.ipv6_interface_id().and_then(|id| id.try_into().ok()),
        smf_ipv6_link_local_address: ie.smf_ipv6_link_local_address().map(Ipv6Addr::from),
    }),
    |_, address| {
        let ipv4 = address.ipv4.map(|ipv4| ipv4.octets());
        let smf = address.smf_ipv6_link_local_address.map(|smf| smf.octets());
        Some(match (ipv4, address.ipv6_interface_id, smf) {
            (Some(ipv4), None, None) => NasPduAddress::from_ipv4(ipv4),
            (None, Some(id), None) => NasPduAddress::from_ipv6_iid(id),
            (Some(ipv4), Some(id), None) => NasPduAddress::from_ipv4v6(id, ipv4),
            (Some(ipv4), None, Some(smf)) => {
                NasPduAddress::from_ipv4_with_smf_ipv6_link_local_address(ipv4, smf)
            }
            (None, Some(id), Some(smf)) => {
                NasPduAddress::from_ipv6_iid_with_smf_ipv6_link_local_address(id, smf)
            }
            (Some(ipv4), Some(id), Some(smf)) => {
                NasPduAddress::from_ipv4v6_with_smf_ipv6_link_local_address(id, ipv4, smf)
            }
            (None, None, _) => return None,
        })
    }
);

/// The maximum data rates of user plane integrity protection.
#[derive(Serialize, Deserialize)]
struct MaximumDataRates {
    ul: MaxDataRate,
    dl: MaxDataRate,
}

decoded_ie!(
    NasIntegrityProtectionMaximumDataRate: MaximumDataRates,
    |ie| Some(MaximumDataRates {
        ul: MaxDataRate::from_u8_strict(ie.ul_raw())?,
        dl: MaxDataRate::from_u8_strict(ie.dl_raw())?,
    }),
    |_, rates| Some(NasIntegrityProtectionMaximumDataRate::from_rates(rates.ul, rates.dl))
);
decoded_ie!(
    NasQosRules: Vec<QosRule>,
    |ie| ie.validate_strict().is_ok().then(|| ie.rules()),
    |_, rules| NasQosRules::try_from_rules(&rules)
);
decoded_ie!(
    NasQosFlowDescriptions: Vec<QosFlowDescription>,
    |ie| ie.try_descriptions(),
    |_, descriptions| NasQosFlowDescriptions::try_from_descriptions(&descriptions)
);

// Capabilities: every flag by its name, and the algorithms by number.
fields_ie!(NasFGmmCapability {} flags);
crate::common::nas_ie_flags!(@named NasFGsNetworkFeatureSupport {
    ims_vops_3gpp ims_vops_n3gpp iwk_n26 mpsi emcn3 mcsi cp_ciot n3_data iphc_cp_ciot up_ciot
    lcs_5g ats_ind ehc_cp_ciot ncr piv rpr pr un_per naps lcs_upp supl rslp mlcsup ef5l
});
fields_ie!(NasFGsNetworkFeatureSupport {
    "emc":
        |ie| Code::of(ie.emc_value(), ie.emc()),
        |ie, code: Code<EmergencyServiceSupport>| if let Code::Name(name) = code {
            ie.set_emc_value(name)
        };
    "emf":
        |ie| Code::of(ie.emf_value(), ie.emf()),
        |ie, code: Code<EmergencyFallbackSupport>| if let Code::Name(name) = code {
            ie.set_emf_value(name)
        };
    "restrict-ec":
        |ie| Code::of(ie.restrict_ec_value(), ie.restrict_ec()),
        |ie, code: Code<RestrictionOnEnhancedCoverage>| if let Code::Name(name) = code {
            ie.set_restrict_ec_value(name)
        };
} flags);
crate::common::nas_ie_flags!(@named NasFGsmCapability {
    tpmic ept_s1 mh6_pdu rqos mpquic_ip mpquic_udp mptcp rtpmmii sdnaepc apmqf e8pcpdei mpquic_e
});
fields_ie!(NasFGsmCapability {
    "atsss-st":
        |ie| Code::of(ie.atsss_st_value(), ie.atsss_st()),
        |ie, code: Code<AtsssSteeringFunctionality>| if let Code::Name(name) = code {
            ie.set_atsss_st_value(name)
        };
    "atsss-ll":
        |ie| Code::of(ie.atsss_ll_value(), ie.atsss_ll()),
        |ie, code: Code<AtsssLowLayerFunctionality>| if let Code::Name(name) = code {
            ie.set_atsss_ll_value(name)
        };
} flags);
fields_ie!(NasS1UeNetworkCapability {
    "eea": |ie| supported(ie, Self::supports_eea), |ie, algorithms: Vec<u16>| {
        (0..8).for_each(|algorithm| ie.set_eea(algorithm, algorithms.contains(&algorithm.into())));
    };
    "eia": |ie| supported(ie, Self::supports_eia), |ie, algorithms: Vec<u16>| {
        (0..8).for_each(|algorithm| ie.set_eia(algorithm, algorithms.contains(&algorithm.into())));
    };
} flags);
fields_ie!(NasS1UeSecurityCapability {
    "eea": |ie| supported(ie, Self::supports_eea), |ie, algorithms: Vec<u16>| {
        (0..8).for_each(|algorithm| ie.set_eea(algorithm, algorithms.contains(&algorithm.into())));
    };
    "eia": |ie| supported(ie, Self::supports_eia), |ie, algorithms: Vec<u16>| {
        (0..8).for_each(|algorithm| ie.set_eia(algorithm, algorithms.contains(&algorithm.into())));
    };
} flags);

// Read only. The crate parses these; their builders take the parsed entries
// and have not been driven with values that a parser does not produce, so
// the view does not hand them what an author writes.
decoded_ie!(NasNsagInformation: Vec<NsagInfoEntry>, |ie| ie
    .is_well_formed()
    .then(|| ie.entries()));
decoded_ie!(NasNssrgInformation: Vec<NssrgInfoEntry>, |ie| ie
    .is_well_formed()
    .then(|| ie.entries()));
decoded_ie!(NasLadnInformation: Vec<LadnInfoEntry>, |ie| ie
    .is_well_formed()
    .then(|| ie.entries()));
decoded_ie!(NasCagInformationList: Vec<CagInformationEntry>, |ie| ie
    .is_well_formed()
    .then(|| ie.entries()));
decoded_ie!(NasExtendedCagInformationList: Vec<CagInformationEntry>, |ie| ie
    .is_well_formed()
    .then(|| ie.entries()));
decoded_ie!(NasServiceAreaList: Vec<ServiceAreaListEntry>, |ie| ie
    .receiver_syntax_is_valid()
    .then(|| ie.entries()));
decoded_ie!(
    NasExtendedRejectedNssai: Vec<ExtendedRejectedNssaiPartialList>,
    |ie| ie.is_well_formed().then(|| ie.partial_lists())
);
decoded_ie!(
    NasOperatorDefinedAccessCategoryDefinitions: Vec<OperatorAccessCategoryDefinition>,
    |ie| ie.try_definitions()
);
decoded_ie!(
    NasPduSessionReactivationResultErrorCause: Vec<(u8, GmmCause)>,
    |ie| ie.is_well_formed().then(|| ie.entries())
);
decoded_ie!(NasMappedEpsBearerContexts: Vec<MappedEpsBearerContext>, |ie| ie.try_contexts());
decoded_ie!(NasReceivedMbsContainer: Vec<ReceivedMbsSession>, |ie| ie.try_sessions());
decoded_ie!(NasRequestedMbsContainer: Vec<RequestedMbsSession>, |ie| ie.try_sessions());
decoded_ie!(NasSorTransparentContainer: SorTransparentContainerContents, |ie| ie.parse());
decoded_ie!(
    NasUeParametersUpdateTransparentContainer: UeParametersUpdateTransparentContainerContents,
    |ie| ie.parse()
);
decoded_ie!(NasCiotSmallDataContainer: CiotSmallDataContainerContents, |ie| ie.parse());
decoded_ie!(NasN3Qai: Vec<N3QaiEntry>, |ie| ie.try_entries());
decoded_ie!(NasProtocolDescription: Vec<ProtocolDescriptionEntry>, |ie| ie
    .is_well_formed()
    .then(|| ie.entries()));
decoded_ie!(NasType6IeContainer: Vec<Type6IeContainerEntry>, |ie| ie
    .is_well_formed()
    .then(|| ie.entries()));
decoded_ie!(
    NasSNssaiLocationValidityInformation: Vec<SNssaiLocationValidityEntry>,
    |ie| ie.is_well_formed().then(|| ie.entries())
);
decoded_ie!(NasRelayKeyRequestParameters: RelayKeyRequestParameters, |ie| ie.parse());
decoded_ie!(NasRelayKeyResponseParameters: RelayKeyResponseParameters, |ie| ie.parse());
decoded_ie!(NasServiceLevelAaContainer: Vec<ServiceLevelAaParameter>, |ie| ie
    .try_parameters()
    .ok());
decoded_ie!(NasN3iwfIdentifier: N3iwfAddress, |ie| ie.address());
listed_ie!(NasAlternativeNssai: AlternativeNssaiEntry, entries, |entries| {
    Self::try_from_entries(entries).ok()
});
listed_ie!(NasOnDemandNssai: OnDemandNssaiEntry, entries, |entries| {
    Self::try_from_entries(entries).ok()
});
listed_ie!(NasPartialNssai: PartialNssaiEntry, entries, |entries| {
    Self::try_from_entries(entries).ok()
});
listed_ie!(NasExtendedLadnInformation: ExtendedLadnInformationEntry, entries, Self::from_entries);
listed_ie!(NasNon3GppDelayBudget: Non3GppDelayBudgetEntry, entries, Self::from_entries);
listed_ie!(NasRemoteUeContextList: RemoteUeContext, contexts, Self::from_contexts);
listed_ie!(
    NasSNssaiTimeValidityInformation: SNssaiTimeValidityEntry,
    entries,
    Self::from_entries
);
listed_ie!(NasUrspRuleEnforcementReports: UrspRuleEnforcementReport, reports, Self::from_reports);
listed_ie!(NasCipheringKeyData: CipheringDataSet, data_sets, Self::from_data_sets);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::view::tests::{exercise, sweep};

    #[test]
    fn values_encode_back_and_take_nothing_unchecked() {
        for value in [1, 0x16, 0x79, 0xff] {
            sweep(NasIpHeaderCompressionConfiguration::new(vec![value; 3]));
            sweep(NasIpHeaderCompressionConfiguration::new(vec![
                value & 0x7f,
                0,
                value,
                value & 7,
                value,
            ]));
            sweep(NasPagingRestriction::new(vec![value & 0x0f]));
            sweep(NasPagingRestriction::new(vec![3, value & 0xfe, value]));
            sweep(NasTnanInformation::new(vec![value & 3, 1, value, 1, 0x41]));
            sweep(NasLpWuspsAssistanceInformation::new(vec![value]));
            sweep(NasUeDsTtResidenceTime::new(vec![value; 8]));
            sweep(NasFGmmCause::new(value));
            sweep(NasFGsmCause::new(value));
            sweep(NasFGsIdentityType::new(value));
            sweep(NasPduSessionType::new(value));
            sweep(NasSscMode::new(value));
            sweep(NasRequestType::new(value));
            sweep(NasAccessType::new(value));
            sweep(NasPayloadContainerType::new(value));
            sweep(NasNssaiInclusionMode::new(value));
            sweep(NasProseRelayTransactionIdentity::new(value));
            sweep(NasFGsRegistrationType::new(value));
            sweep(NasDeRegistrationType::new(value));
            sweep(NasControlPlaneServiceType::new(value));
            sweep(NasSecurityAlgorithms::new(value));
            sweep(NasEpsNasSecurityAlgorithms::new(value));
            sweep(NasKeySetIdentifier::new(value));
            sweep(NasGprsTimer::new(value));
            sweep(NasGprsTimer2::new(vec![value]));
            sweep(NasGprsTimer3::new(vec![value]));
            sweep(NasFGsUpdateType::new(vec![value]));
            sweep(NasFGsRegistrationResult::new(vec![value]));
            sweep(NasFGmmCapability::new(vec![value]));
            sweep(NasFGmmCapability::new(vec![value; 13]));
            sweep(NasFGsmCapability::new(vec![value]));
            sweep(NasFGsmCapability::new(vec![value; 3]));
            sweep(NasFGsNetworkFeatureSupport::new(vec![value]));
            sweep(NasFGsNetworkFeatureSupport::new(vec![value; 4]));
            sweep(NasS1UeNetworkCapability::new(vec![value; 2]));
            sweep(NasS1UeNetworkCapability::new(vec![value; 9]));
            sweep(NasS1UeSecurityCapability::new(vec![value; 5]));
            sweep(NasUeSecurityCapability::new(vec![value; 2]));
            sweep(NasUeSecurityCapability::new(vec![value; 4]));
            sweep(NasPduSessionStatus::new(vec![value; 2]));
            sweep(NasUplinkDataStatus::new(vec![value; 2]));
            sweep(NasAllowedPduSessionStatus::new(vec![value; 2]));
            sweep(NasPduSessionReactivationResult::new(vec![value; 2]));
            sweep(NasEpsBearerContextStatus::new(vec![value & 0xfe, value]));
            sweep(NasUeStatus::new(vec![value]));
            sweep(NasReAttemptIndicator::new(vec![value]));
            sweep(NasExtendedDrxParameters::new(vec![value]));
            sweep(NasTimeZoneAndTime::new(vec![value & 0x11; 7]));
            sweep(NasAdditional5gSecurityInformation::new(vec![value]));
            sweep(NasAdditionalConfigurationIndication::new(value & 0x0f));
            sweep(NasAdditionalInformationRequested::new(vec![value]));
            sweep(NasAllowedSscMode::new(value & 0x0f));
            sweep(NasAlwaysOnPduSessionIndication::new(value & 0x0f));
            sweep(NasAlwaysOnPduSessionRequested::new(value & 0x0f));
            sweep(NasAun3Indication::new(vec![value]));
            sweep(NasConfigurationUpdateIndication::new(value & 0x0f));
            sweep(NasControlPlaneOnlyIndication::new(value & 0x0f));
            sweep(NasExtendedFGmmCause::new(vec![value]));
            sweep(NasFGsmCongestionReAttemptIndicator::new(vec![value]));
            sweep(NasFGsmNetworkFeatureSupport::new(vec![value]));
            sweep(NasFeatureAuthorizationIndication::new(vec![value]));
            sweep(NasLpWusStatus::new(value & 0x0f));
            sweep(NasMicoIndication::new(value & 0x0f));
            sweep(NasN5gcIndication::new(value & 0x0f));
            sweep(NasNetworkSlicingIndication::new(value & 0x0f));
            sweep(NasNon3GppAccessPathSwitchingIndication::new(vec![value]));
            sweep(NasNon3GppPathSwitchingInformation::new(vec![value]));
            sweep(NasPayloadContainerInformation::new(value & 0x0f));
            sweep(NasPriorityIndicator::new(value & 0x0f));
            sweep(NasRanTimingSynchronization::new(vec![value]));
            sweep(NasSmsIndication::new(value & 0x0f));
            sweep(NasUeUsageSetting::new(vec![value]));
            sweep(NasTruncatedFGSTmsiConfiguration::new(vec![value]));
            sweep(NasRegistrationWaitRange::new(vec![value, value]));
            sweep(NasAun3DeviceSecurityKey::new(vec![
                value & 1,
                2,
                0xaa,
                0xbb,
            ]));
            sweep(NasPduSessionIdentity2::new(value));
            sweep(NasPduSessionPairId::new(vec![value]));
            sweep(NasMaximumNumberOfSupportedPacketFilters::new(vec![
                value,
                value & 0xe0,
            ]));
            sweep(NasN1ModeToS1ModeNasTransparentContainer::new(value));
            sweep(NasTimeDuration::new(vec![value, value]));
            sweep(NasEcnMarkingL4sIndication::new(vec![value & 0x3f]));
            sweep(NasWusAssistanceInformation::new(vec![value]));
            sweep(NasEthernetHeaderCompressionConfiguration::new(vec![value]));
            sweep(NasImeisvRequest::new(value & 0x0f));
            sweep(NasFGsDrxParameters::new(vec![value]));
            sweep(NasRsn::new(vec![value]));
            sweep(NasIntegrityProtectionMaximumDataRate::new(
                u16::from(value) * 0x0101,
            ));
            sweep(NasUnavailabilityInformation::new(vec![
                value & 0x1f,
                0,
                0,
                value,
            ]));
            sweep(NasUnavailabilityConfiguration::new(vec![
                value & 0x1f,
                0,
                0,
                value,
            ]));
        }
        let plmn = [0x02, 0xf8, 0x39];
        let octets = |parts: &[&[u8]]| parts.concat();
        for identity in [
            octets(&[&[0x01], &plmn, &[0, 0, 0, 0, 0, 0, 0, 0, 0x10]]),
            octets(&[&[0x01], &plmn, &[0xf0, 0xff, 1, 2, 0xaa, 0xbb, 0xcc]]),
            octets(&[&[0xf2], &plmn, &[1, 0, 0x42, 0x11, 0x22, 0x33, 0x44]]),
            vec![0xf4, 0, 0x42, 0x11, 0x22, 0x33, 0x44],
            vec![0x4b, 0x09, 0x51, 0x24, 0x30, 0x32, 0x57, 0x81],
            vec![0x45, 0x09, 0x51, 0x24, 0x30, 0x32, 0x57, 0x81, 0xf1],
            vec![0x0e, 1, 2, 3, 4, 5, 6],
            vec![0x07, 1, 2, 3, 4, 5, 6, 7, 8],
            vec![0x00],
        ] {
            exercise(NasFGsMobileIdentity::new(identity));
        }
        let nai = "type1.rid678.schid0.useriduser17@example.com";
        exercise(NasFGsMobileIdentity::from_suci_nai(SupiFormat::NetworkSpecific, nai).unwrap());
        exercise(NasDsTtEthernetPortMacAddress::new(vec![1, 2, 3, 4, 5, 6]));
        exercise(NasFGsTrackingAreaIdentity::new(octets(&[
            &plmn,
            &[0, 0, 1],
        ])));
        for list in [
            octets(&[&[0x01], &plmn, &[0, 0, 1, 0, 0, 2]]),
            octets(&[&[0x21], &plmn, &[0, 0, 1]]),
            octets(&[&[0x41], &plmn, &[0, 0, 1], &plmn, &[0, 0, 2]]),
        ] {
            exercise(NasFGsTrackingAreaIdentityList::new(list));
        }
        exercise(NasPlmnList::new(octets(&[&plmn, &[0x02, 0x18, 0x39]])));
        exercise(NasListOfPlmnsToBeUsedInDisasterCondition::new(
            plmn.to_vec(),
        ));
        exercise(NasPlmnIdentity::new(plmn.to_vec()));
        exercise(NasSNssai::new(vec![1, 1, 2, 3]));
        exercise(NasNssai::new(vec![4, 1, 1, 2, 3, 1, 2]));
        exercise(NasMappedNssai::new(vec![1, 1, 4, 1, 1, 2, 3]));
        exercise(NasRejectedNssai::new(vec![0x10, 1, 0x41, 2, 1, 2, 3]));
        exercise(NasLadnIndication::new(
            b"\x09\x08internet\x04\x03ims".to_vec(),
        ));
        exercise(NasDnn::new(b"\x08internet".to_vec()));
        exercise(NasNid::from_nid_value("000007ed9d5a").unwrap());
        exercise(NasSmPduDnRequestContainer::from_str("user@example.com"));
        exercise(NasSessionAmbr::new(vec![6, 0, 100, 6, 0, 50]));
        exercise(NasPduAddress::new(vec![1, 10, 0, 0, 1]));
        exercise(NasPduAddress::new(vec![2, 1, 2, 3, 4, 5, 6, 7, 8]));
        exercise(NasPduAddress::new(vec![
            3, 1, 2, 3, 4, 5, 6, 7, 8, 10, 0, 0, 1,
        ]));
        exercise(NasPduAddress::new(octets(&[
            &[9, 10, 0, 0, 1],
            &[0xfe; 16],
        ])));
        // One QoS rule: create, default, precedence 255, QFI 1, match-all filter.
        exercise(NasQosRules::new(vec![1, 0, 6, 0x31, 0x31, 1, 1, 255, 1]));
        // One QoS flow description: create QFI 1 with a 5QI of 9.
        exercise(NasQosFlowDescriptions::new(vec![1, 0x20, 0x41, 1, 1, 9]));
        exercise(NasNetworkName::from_name("Open5GS", true));
        exercise(NasTimeZone::new(0x40));
        exercise(NasEmergencyNumberList::new(vec![3, 0x1f, 0x11, 0xf2]));
        exercise(NasServingPlmnRateControl::new(vec![0, 10]));
        exercise(NasSupportedCodecList::new(vec![4, 2, 0x60, 0]));
        // A container of a 5GMM STATUS with cause #22, and read-only values.
        exercise(NasMessageContainer::new(vec![0x7e, 0x00, 0x64, 0x16]));
        exercise(NasServiceAreaList::new(octets(&[
            &[0x00],
            &plmn,
            &[0, 0, 1],
        ])));
    }
}
