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

//! The contents of a payload container of the type "event notification" or
//! "multiple payloads" (TS 24.501 §9.11.3.39).

use crate::common::{Error, Reader, Result};
use crate::nas_5gs::{
    Dnn, GmmCause, GprsTimer3, MaPduSessionInformation, PduSessionIdentity2,
    ReleaseAssistanceIndication, RequestType, SNssai,
};
use crate::prelude::*;

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
/// An optional IE of a payload container entry (TS 24.501 Table 9.11.3.39.1).
pub enum MultiplePayloadOptionalIe {
    /// PDU session identifier.
    PduSessionId(PduSessionIdentity2),
    /// Additional information.
    AdditionalInformation(crate::nas_5gs::AdditionalInformation),
    /// 5GMM cause.
    FiveGmmCause(GmmCause),
    /// Back-off timer value.
    BackOffTimerValue(GprsTimer3),
    /// Old PDU session identifier.
    OldPduSessionId(PduSessionIdentity2),
    /// Request type.
    RequestType(RequestType),
    /// S-NSSAI.
    SNssai(SNssai),
    /// DNN.
    Dnn(Dnn),
    /// Release assistance indication.
    ReleaseAssistanceIndication(ReleaseAssistanceIndication),
    /// MA PDU session information.
    MaPduSessionInformation(MaPduSessionInformation),
    /// Unknown.
    Unknown {
        /// Information-element identifier.
        iei: u8,
        /// Raw information-element contents.
        value: Vec<u8>,
    },
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(enum MultiplePayloadOptionalIe { PduSessionId(PduSessionIdentity2 as tree), AdditionalInformation(crate::nas_5gs::AdditionalInformation as tree), FiveGmmCause(GmmCause as tree), BackOffTimerValue(GprsTimer3 as tree), OldPduSessionId(PduSessionIdentity2 as tree), RequestType(RequestType as tree), SNssai(SNssai as tree), Dnn(Dnn as tree), ReleaseAssistanceIndication(ReleaseAssistanceIndication as tree), MaPduSessionInformation(MaPduSessionInformation as tree), Unknown { iei, value } });
#[cfg(feature = "tree")]
crate::common::readable::serde_by_readable!(MultiplePayloadOptionalIe);

impl MultiplePayloadOptionalIe {
    /// Return IEI.
    pub fn iei(&self) -> u8 {
        match self {
            Self::PduSessionId(_) => 0x12,
            Self::AdditionalInformation(_) => 0x24,
            Self::FiveGmmCause(_) => 0x58,
            Self::BackOffTimerValue(_) => 0x37,
            Self::OldPduSessionId(_) => 0x59,
            Self::RequestType(_) => 0x80,
            Self::SNssai(_) => 0x22,
            Self::Dnn(_) => 0x25,
            Self::ReleaseAssistanceIndication(_) => 0xF0,
            Self::MaPduSessionInformation(_) => 0xA0,
            Self::Unknown { iei, .. } => *iei,
        }
    }

    /// Return the decoded value.
    pub fn value(&self) -> Vec<u8> {
        match self {
            Self::PduSessionId(ie) => vec![ie.value],
            Self::AdditionalInformation(ie) => ie.value.to_vec(),
            Self::FiveGmmCause(ie) => vec![ie.value],
            Self::BackOffTimerValue(ie) => ie.value.to_vec(),
            Self::OldPduSessionId(ie) => vec![ie.value],
            Self::RequestType(ie) => vec![ie.value],
            Self::SNssai(ie) => ie.value.to_vec(),
            Self::Dnn(ie) => ie.value.to_vec(),
            Self::ReleaseAssistanceIndication(ie) => vec![ie.value],
            Self::MaPduSessionInformation(ie) => vec![ie.value],
            Self::Unknown { value, .. } => value.clone(),
        }
    }

    /// The optional IE of the identifier `iei` with the octets `value`. An
    /// IE whose value is one octet is read as its type when it has that one
    /// octet, and is [`Self::Unknown`] with what it has otherwise, so that
    /// its octets are kept as they came.
    pub fn from_raw(iei: u8, value: Vec<u8>) -> Self {
        let octet = match value.as_slice() {
            [octet] => Some(*octet),
            _ => None,
        };
        match (iei, octet) {
            (0x12, Some(octet)) => Self::PduSessionId(PduSessionIdentity2::new(octet)),
            (0x24, _) => {
                Self::AdditionalInformation(crate::nas_5gs::AdditionalInformation::new(value))
            }
            (0x58, Some(octet)) => Self::FiveGmmCause(GmmCause::new(octet)),
            (0x37, _) => Self::BackOffTimerValue(GprsTimer3::new(value)),
            (0x59, Some(octet)) => Self::OldPduSessionId(PduSessionIdentity2::new(octet)),
            (0x80, Some(octet)) => Self::RequestType(RequestType::new(octet)),
            (0x22, _) => Self::SNssai(SNssai::new(value)),
            (0x25, _) => Self::Dnn(Dnn::new(value)),
            (0xF0, Some(octet)) => {
                Self::ReleaseAssistanceIndication(ReleaseAssistanceIndication::new(octet))
            }
            (0xA0, Some(octet)) => {
                Self::MaPduSessionInformation(MaPduSessionInformation::new(octet))
            }
            _ => Self::Unknown { iei, value },
        }
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The type of an event notification indicator (TS 24.501 §9.11.3.39).
pub enum EventNotificationIndicatorType {
    /// SRVCC handover cancelled, IMS session re-establishment required.
    SrvccHandoverCancelledImsSessionReEstablishmentRequired,
    /// Unknown.
    Unknown(u8),
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(
    enum EventNotificationIndicatorType {
        SrvccHandoverCancelledImsSessionReEstablishmentRequired,
        Unknown(u8),
    }
);
#[cfg(feature = "tree")]
crate::common::readable::serde_by_readable!(EventNotificationIndicatorType);

impl EventNotificationIndicatorType {
    /// Decode a value from its wire octet.
    pub fn from_u8(value: u8) -> Self {
        match value {
            0x00 => Self::SrvccHandoverCancelledImsSessionReEstablishmentRequired,
            other => Self::Unknown(other),
        }
    }

    /// Return the wire octet.
    pub fn as_u8(self) -> u8 {
        match self {
            Self::SrvccHandoverCancelledImsSessionReEstablishmentRequired => 0x00,
            Self::Unknown(value) => value,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// An event notification indicator: its type and its value.
pub struct EventNotificationIndicator {
    /// Indicator type.
    pub indicator_type: EventNotificationIndicatorType,
    /// Raw information-element contents.
    pub value: Vec<u8>,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(struct EventNotificationIndicator { indicator_type, value });
#[cfg(feature = "tree")]
crate::common::readable::serde_by_readable!(EventNotificationIndicator);

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
/// The event notification indicators of a payload container of the type
/// "event notification".
pub struct EventNotificationContainer {
    /// Indicators.
    pub indicators: Vec<EventNotificationIndicator>,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(struct EventNotificationContainer { indicators });
#[cfg(feature = "tree")]
crate::common::readable::serde_by_readable!(EventNotificationContainer);

impl EventNotificationContainer {
    /// The value of its members, in their order. A later version may add a
    /// member that this leaves at its default.
    pub fn new(indicators: Vec<EventNotificationIndicator>) -> Self {
        Self { indicators }
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
/// A payload container entry of a payload container of the type "multiple
/// payloads": its type, its optional IEs and its contents.
pub struct MultiplePayloadEntry {
    /// Payload container type.
    pub payload_container_type: crate::nas_5gs::PayloadContainerType,
    /// Optional ies.
    pub optional_ies: Vec<MultiplePayloadOptionalIe>,
    /// Encoded contents.
    pub contents: Vec<u8>,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(struct MultiplePayloadEntry { payload_container_type as tree, optional_ies, contents });
#[cfg(feature = "tree")]
crate::common::readable::serde_by_readable!(MultiplePayloadEntry);

impl MultiplePayloadEntry {
    /// The value of its members, in their order. A later version may add a
    /// member that this leaves at its default.
    pub fn new(
        payload_container_type: crate::nas_5gs::PayloadContainerType,
        optional_ies: Vec<MultiplePayloadOptionalIe>,
        contents: Vec<u8>,
    ) -> Self {
        Self {
            payload_container_type,
            optional_ies,
            contents,
        }
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
/// The payload container entries of a payload container of the type
/// "multiple payloads".
pub struct MultiplePayloadContainer {
    /// Entries.
    pub entries: Vec<MultiplePayloadEntry>,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(struct MultiplePayloadContainer { entries });
#[cfg(feature = "tree")]
crate::common::readable::serde_by_readable!(MultiplePayloadContainer);

impl MultiplePayloadContainer {
    /// The value of its members, in their order. A later version may add a
    /// member that this leaves at its default.
    pub fn new(entries: Vec<MultiplePayloadEntry>) -> Self {
        Self { entries }
    }
}

impl EventNotificationContainer {
    /// Decode the value from its wire representation.
    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut buffer = data;
        if !buffer.has_remaining() {
            return Ok(Self::default());
        }
        let indicator_count = buffer.get_u8() as usize;
        let mut indicators = Vec::with_capacity(indicator_count);
        for _ in 0..indicator_count {
            if buffer.remaining() < 2 {
                return Err(Error::BufferTooShort);
            }
            let indicator_type = EventNotificationIndicatorType::from_u8(buffer.get_u8());
            let length = buffer.get_u8() as usize;
            if buffer.remaining() < length {
                return Err(Error::BufferTooShort);
            }
            let value = buffer.split_to(length).to_vec();
            if matches!(
                indicator_type,
                EventNotificationIndicatorType::SrvccHandoverCancelledImsSessionReEstablishmentRequired
            ) && !value.is_empty()
            {
                return Err(Error::DecodingError(
                    "SRVCC handover cancelled indicator shall not include a value field".into(),
                ));
            }
            indicators.push(EventNotificationIndicator {
                indicator_type,
                value,
            });
        }
        Ok(Self { indicators })
    }

    /// Encode the value into its wire representation.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(1 + self.indicators.len() * 2);
        out.push(self.indicators.len().try_into().map_err(|_| {
            Error::EncodingError("event notification indicator count exceeds 255".into())
        })?);
        for indicator in &self.indicators {
            if matches!(
                indicator.indicator_type,
                EventNotificationIndicatorType::SrvccHandoverCancelledImsSessionReEstablishmentRequired
            ) && !indicator.value.is_empty()
            {
                return Err(Error::EncodingError(
                    "SRVCC handover cancelled indicator shall not include a value field".into(),
                ));
            }
            out.push(indicator.indicator_type.as_u8());
            out.push(indicator.value.len().try_into().map_err(|_| {
                Error::EncodingError("event notification indicator value exceeds 255 octets".into())
            })?);
            out.extend_from_slice(&indicator.value);
        }
        Ok(out)
    }
}

impl MultiplePayloadContainer {
    /// Decode the value from its wire representation.
    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut buffer = data;
        if !buffer.has_remaining() {
            return Ok(Self::default());
        }
        let entry_count = buffer.get_u8() as usize;
        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            if buffer.remaining() < 3 {
                return Err(Error::BufferTooShort);
            }
            let entry_len = usize::from(buffer.get_u16());
            if buffer.remaining() < entry_len {
                return Err(Error::BufferTooShort);
            }
            let mut entry_bytes = buffer.split_to(entry_len);
            if !entry_bytes.has_remaining() {
                return Err(Error::BufferTooShort);
            }
            let header = entry_bytes.get_u8();
            let optional_ie_count = (header >> 4) as usize;
            let payload_container_type = crate::nas_5gs::PayloadContainerType::new(header & 0x0F);
            let mut optional_ies = Vec::with_capacity(optional_ie_count);
            for _ in 0..optional_ie_count {
                if entry_bytes.remaining() < 2 {
                    return Err(Error::BufferTooShort);
                }
                let iei = entry_bytes.get_u8();
                let length = entry_bytes.get_u8() as usize;
                if entry_bytes.remaining() < length {
                    return Err(Error::BufferTooShort);
                }
                let value = entry_bytes.split_to(length).to_vec();
                optional_ies.push(MultiplePayloadOptionalIe::from_raw(iei, value));
            }
            let contents = entry_bytes.split_to(entry_bytes.remaining()).to_vec();
            entries.push(MultiplePayloadEntry {
                payload_container_type,
                optional_ies,
                contents,
            });
        }
        Ok(Self { entries })
    }

    /// Encode the value into its wire representation.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        out.push(self.entries.len().try_into().map_err(|_| {
            Error::EncodingError("multiple payload entry count exceeds 255".into())
        })?);
        for entry in &self.entries {
            let mut body = Vec::new();
            let optional_ie_count = u8::try_from(entry.optional_ies.len()).map_err(|_| {
                Error::EncodingError("multiple payload optional IE count exceeds 15".into())
            })?;
            if optional_ie_count > 0x0F {
                return Err(Error::EncodingError(
                    "multiple payload optional IE count exceeds 15".into(),
                ));
            }
            if entry.payload_container_type.value > 0x0F {
                return Err(Error::EncodingError(
                    "multiple payload container type is a half octet of four bits".into(),
                ));
            }
            body.push((optional_ie_count << 4) | entry.payload_container_type.value);
            for optional_ie in &entry.optional_ies {
                let value = optional_ie.value();
                body.push(optional_ie.iei());
                body.push(value.len().try_into().map_err(|_| {
                    Error::EncodingError(
                        "multiple payload optional IE length exceeds 255 octets".into(),
                    )
                })?);
                body.extend_from_slice(&value);
            }
            body.extend_from_slice(&entry.contents);
            out.extend_from_slice(
                &(u16::try_from(body.len()).map_err(|_| {
                    Error::EncodingError(
                        "multiple payload entry length exceeds 65535 octets".into(),
                    )
                })?)
                .to_be_bytes(),
            );
            out.extend_from_slice(&body);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_notification_container_roundtrip() {
        let container = EventNotificationContainer {
            indicators: vec![EventNotificationIndicator {
                indicator_type:
                    EventNotificationIndicatorType::SrvccHandoverCancelledImsSessionReEstablishmentRequired,
                value: Vec::new(),
            }],
        };
        let encoded = container.encode().unwrap();
        let decoded = EventNotificationContainer::decode(&encoded).unwrap();
        assert_eq!(decoded, container);
    }

    #[test]
    fn test_multiple_payload_container_roundtrip() {
        let container = MultiplePayloadContainer {
            entries: vec![MultiplePayloadEntry {
                payload_container_type: crate::nas_5gs::PayloadContainerType::from_kind(
                    crate::nas_5gs::PayloadContainerKind::N1SmInformation,
                ),
                optional_ies: vec![
                    MultiplePayloadOptionalIe::PduSessionId(PduSessionIdentity2::new(5)),
                    MultiplePayloadOptionalIe::RequestType(RequestType::from_request_type(
                        crate::nas_5gs::RequestTypeValue::InitialRequest,
                    )),
                ],
                contents: vec![0x2E, 0x01, 0x01, 0xC1],
            }],
        };
        let encoded = container.encode().unwrap();
        let decoded = MultiplePayloadContainer::decode(&encoded).unwrap();
        assert_eq!(decoded, container);
    }

    #[test]
    fn test_multiple_payload_optional_ies_use_hexadecimal_ieis() {
        // TS 24.501 Table 9.11.3.39.1 lists the optional IEIs 12, 24, 58,
        // 37, 59, 80, 22, 25, F0 and A0, the hexadecimal IEIs of the UL and
        // DL NAS TRANSPORT message tables.
        let optional_ies = vec![
            MultiplePayloadOptionalIe::PduSessionId(PduSessionIdentity2::new(5)),
            MultiplePayloadOptionalIe::AdditionalInformation(
                crate::nas_5gs::AdditionalInformation::new(vec![0x01]),
            ),
            MultiplePayloadOptionalIe::FiveGmmCause(GmmCause::new(0x5a)),
            MultiplePayloadOptionalIe::BackOffTimerValue(GprsTimer3::new(vec![0x21])),
            MultiplePayloadOptionalIe::OldPduSessionId(PduSessionIdentity2::new(6)),
            MultiplePayloadOptionalIe::RequestType(RequestType::new(0x01)),
            MultiplePayloadOptionalIe::SNssai(SNssai::new(vec![0x01])),
            MultiplePayloadOptionalIe::Dnn(Dnn::new(vec![0x03, b'i', b'm', b's'])),
            MultiplePayloadOptionalIe::ReleaseAssistanceIndication(
                ReleaseAssistanceIndication::new(0x01),
            ),
            MultiplePayloadOptionalIe::MaPduSessionInformation(MaPduSessionInformation::new(0x01)),
        ];
        assert_eq!(
            optional_ies
                .iter()
                .map(MultiplePayloadOptionalIe::iei)
                .collect::<Vec<_>>(),
            [0x12, 0x24, 0x58, 0x37, 0x59, 0x80, 0x22, 0x25, 0xf0, 0xa0]
        );
        for optional_ie in &optional_ies {
            assert_eq!(
                &MultiplePayloadOptionalIe::from_raw(optional_ie.iei(), optional_ie.value()),
                optional_ie
            );
        }

        // One N1 SM entry with a DNN optional IE "ims".
        let wire = hex::decode("01000b1125040369 6d732e0101c1".replace(' ', "")).unwrap();
        let decoded = MultiplePayloadContainer::decode(&wire).unwrap();
        assert_eq!(
            decoded.entries[0].optional_ies,
            [MultiplePayloadOptionalIe::Dnn(Dnn::new(vec![
                0x03, b'i', b'm', b's'
            ]))]
        );
    }

    /// An optional IE of one octet that comes with two, or with none, is
    /// kept with the octets that it has: it was read as its first octet,
    /// or as 0, and the entry was encoded with another IE than it came with.
    #[test]
    fn an_optional_ie_of_another_length_keeps_its_octets() {
        // One N1 SM entry: a PDU session ID of two octets, a 5GMM cause
        // without one, and the contents
        let wire = hex::decode("010009211202050658002e01").unwrap();
        let decoded = MultiplePayloadContainer::decode(&wire).unwrap();
        let unknown = |iei, value: &[u8]| MultiplePayloadOptionalIe::Unknown {
            iei,
            value: value.to_vec(),
        };
        assert_eq!(
            decoded.entries[0].optional_ies,
            [unknown(0x12, &[5, 6]), unknown(0x58, &[])]
        );
        assert_eq!(decoded.encode().unwrap(), wire);
        // With its one octet it is the IE
        assert_eq!(
            MultiplePayloadOptionalIe::from_raw(0x12, vec![5]),
            MultiplePayloadOptionalIe::PduSessionId(PduSessionIdentity2::new(5))
        );
        // A payload container type is a half octet: its low bits were written
        let mut wide = decoded.clone();
        wide.entries[0].payload_container_type = crate::nas_5gs::PayloadContainerType::new(0x11);
        assert_eq!(
            wide.encode().unwrap_err().to_string(),
            "cannot encode: multiple payload container type is a half octet of four bits"
        );
    }
}
