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

//! `protect` and `unprotect` of the security contexts, on the plain messages
//! of an input that a context protects.
//!
//! A message is protected in the direction and under the security header
//! type that its type allows, with a COUNT of zero. A call has a context of
//! its own, made before the call: a context counts the messages that it
//! protects. `protect` and `unprotect` are with 128-NIA2 and 128-NEA2, which
//! are AES; on the inputs of one message of a given size they are also
//! measured with SNOW 3G (`protect-snow3g`) and with ZUC (`protect-zuc`).

use crate::{Messages, Operation, done, prepared};
use oxirush_nas::common::Direction;
use oxirush_nas::{nas_5gs, nas_eps};
use std::hint::black_box;

/// A message of an input as a context protects it.
pub(crate) struct Message<H> {
    /// Its place in the input.
    at: usize,
    direction: Direction,
    header: H,
    /// The protected message.
    wire: Vec<u8>,
}

/// The pairs of algorithms that are measured: the names of `protect` and
/// of `unprotect` with each, and its number in the two specifications.
const ALGORITHMS: [(&str, &str, u8); 3] = [
    ("protect", "unprotect", 2),
    ("protect-snow3g", "unprotect-snow3g", 1),
    ("protect-zuc", "unprotect-zuc", 3),
];

/// The messages of an input that a context protects, with each pair of
/// algorithms.
pub(crate) enum Protected {
    FiveGs([Vec<Message<nas_5gs::Nas5gsSecurityHeaderType>>; 3]),
    Eps([Vec<Message<nas_eps::NasEpsSecurityHeaderType>>; 3]),
}

fn context_5gs(algorithm: u8) -> nas_5gs::NasSecurityContext {
    use nas_5gs::{CipheringAlgorithm as Nea, IntegrityAlgorithm as Nia, KNasEnc, KNasInt};
    let (nia, nea) = match algorithm {
        1 => (Nia::NIA1, Nea::NEA1),
        2 => (Nia::NIA2, Nea::NEA2),
        _ => (Nia::NIA3, Nea::NEA3),
    };
    let (knas_int, knas_enc) = (KNasInt::new(&[0x11; 16]), KNasEnc::new(&[0x22; 16]));
    nas_5gs::NasSecurityContext::from_fresh_keys(&knas_int, &knas_enc, nia, nea).unwrap()
}

fn context_eps(algorithm: u8) -> nas_eps::NasSecurityContext {
    use nas_eps::{CipheringAlgorithm as Eea, IntegrityAlgorithm as Eia, KNasEnc, KNasInt};
    let (eia, eea) = match algorithm {
        1 => (Eia::EIA1, Eea::EEA1),
        2 => (Eia::EIA2, Eea::EEA2),
        _ => (Eia::EIA3, Eea::EEA3),
    };
    let (knas_int, knas_enc) = (KNasInt::new(&[0x11; 16]), KNasEnc::new(&[0x22; 16]));
    nas_eps::NasSecurityContext::from_fresh_keys(&knas_int, &knas_enc, eia, eea).unwrap()
}

/// The first direction and header type that protect a message, with what
/// `protect` gives for them.
fn first<H: Copy>(
    at: usize,
    headers: &[H],
    protect: impl Fn(H, Direction) -> Option<Vec<u8>>,
) -> Option<Message<H>> {
    let directions = [Direction::Uplink, Direction::Downlink];
    headers.iter().find_map(|header| {
        directions.iter().find_map(|direction| {
            Some(Message {
                at,
                direction: *direction,
                header: *header,
                wire: protect(*header, *direction)?,
            })
        })
    })
}

impl Protected {
    pub(crate) fn of(messages: &Messages) -> Self {
        match messages {
            Messages::FiveGs(messages) => {
                use nas_5gs::Nas5gsSecurityHeaderType as Header;
                let headers = [
                    Header::IntegrityProtectedAndCiphered,
                    Header::IntegrityProtectedWithNewFiveGNasSecurityContext,
                    Header::IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext,
                ];
                Self::FiveGs(ALGORITHMS.map(|(_, _, algorithm)| {
                    let protected = |(at, (_, message)): (usize, &(Vec<u8>, _))| {
                        first(at, &headers, |header, direction| {
                            (context_5gs(algorithm).protect(message, header, direction)).ok()
                        })
                    };
                    messages.iter().enumerate().filter_map(protected).collect()
                }))
            }
            Messages::Eps(messages) => {
                use nas_eps::NasEpsSecurityHeaderType as Header;
                let headers = [
                    Header::IntegrityProtectedAndCiphered,
                    Header::IntegrityProtected,
                    Header::IntegrityProtectedWithNewEpsSecurityContext,
                    Header::IntegrityProtectedAndCipheredWithNewEpsSecurityContext,
                    Header::IntegrityProtectedAndPartiallyCipheredNasMessage,
                ];
                Self::Eps(ALGORITHMS.map(|(_, _, algorithm)| {
                    let protected = |(at, message): (usize, &(Vec<u8>, Direction, _))| {
                        first(at, &headers, |header, direction| {
                            (context_eps(algorithm).protect(&message.2, header, direction)).ok()
                        })
                    };
                    messages.iter().enumerate().filter_map(protected).collect()
                }))
            }
        }
    }

    /// `protect` and `unprotect` on the messages that a context protects,
    /// with AES, and with the two other algorithms too when `every` is set;
    /// none for an input without such a message.
    pub(crate) fn operations<'a>(
        &'a self,
        messages: &'a Messages,
        every: bool,
    ) -> Vec<Operation<'a>> {
        let measured = if every { 3 } else { 1 };
        let mut operations = Vec::new();
        for (at, (protect, unprotect, algorithm)) in ALGORITHMS.into_iter().enumerate() {
            match (self, messages) {
                (Self::FiveGs(protected), Messages::FiveGs(messages)) if at < measured => {
                    let protected = &protected[at];
                    let count = protected.len();
                    if count == 0 {
                        continue;
                    }
                    operations.push(prepared(protect, count, move |at| {
                        let (mut context, protected) = (context_5gs(algorithm), &protected[at]);
                        let message = black_box(&messages[protected.at].1);
                        move || {
                            done(context.protect(message, protected.header, protected.direction))
                        }
                    }));
                    operations.push(prepared(unprotect, count, move |at| {
                        let (mut context, protected) = (context_5gs(algorithm), &protected[at]);
                        let wire = black_box(&protected.wire);
                        move || done(context.unprotect(wire, protected.direction))
                    }));
                }
                (Self::Eps(protected), Messages::Eps(messages)) if at < measured => {
                    let protected = &protected[at];
                    let count = protected.len();
                    if count == 0 {
                        continue;
                    }
                    operations.push(prepared(protect, count, move |at| {
                        let (mut context, protected) = (context_eps(algorithm), &protected[at]);
                        let message = black_box(&messages[protected.at].2);
                        move || {
                            done(context.protect(message, protected.header, protected.direction))
                        }
                    }));
                    operations.push(prepared(unprotect, count, move |at| {
                        let (mut context, protected) = (context_eps(algorithm), &protected[at]);
                        let wire = black_box(&protected.wire);
                        move || done(context.unprotect(wire, protected.direction))
                    }));
                }
                _ => {}
            }
        }
        operations
    }
}
