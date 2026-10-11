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
//! type that its type allows, with 128-NIA2 and 128-NEA2 and a COUNT of
//! zero. A call has a context of its own, made before the call: a context
//! counts the messages that it protects.

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

/// The messages of an input that a context protects.
pub(crate) enum Protected {
    FiveGs(Vec<Message<nas_5gs::Nas5gsSecurityHeaderType>>),
    Eps(Vec<Message<nas_eps::NasEpsSecurityHeaderType>>),
}

fn context_5gs() -> nas_5gs::NasSecurityContext {
    use nas_5gs::{CipheringAlgorithm, IntegrityAlgorithm};
    let (nia, nea) = (IntegrityAlgorithm::NIA2, CipheringAlgorithm::NEA2);
    nas_5gs::NasSecurityContext::from_fresh_keys([0x11; 16], [0x22; 16], nia, nea).unwrap()
}

fn context_eps() -> nas_eps::NasSecurityContext {
    use nas_eps::{CipheringAlgorithm, IntegrityAlgorithm};
    let (eia, eea) = (IntegrityAlgorithm::EIA2, CipheringAlgorithm::EEA2);
    nas_eps::NasSecurityContext::from_fresh_keys([0x11; 16], [0x22; 16], eia, eea).unwrap()
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
                    Header::IntegrityProtectedWithNewContext,
                    Header::IntegrityProtectedAndCipheredWithNewContext,
                ];
                let protected =
                    |(at, (_, message)): (usize, &(Vec<u8>, nas_5gs::Nas5gsMessage))| {
                        first(at, &headers, |header, direction| {
                            context_5gs().protect(message, header, direction).ok()
                        })
                    };
                Self::FiveGs(messages.iter().enumerate().filter_map(protected).collect())
            }
            Messages::Eps(messages) => {
                use nas_eps::NasEpsSecurityHeaderType as Header;
                let headers = [
                    Header::IntegrityProtectedAndCiphered,
                    Header::IntegrityProtected,
                    Header::IntegrityProtectedWithNewContext,
                    Header::IntegrityProtectedAndCipheredWithNewContext,
                    Header::IntegrityProtectedAndPartiallyCiphered,
                ];
                let protected =
                    |(at, message): (usize, &(Vec<u8>, Direction, nas_eps::NasEpsMessage))| {
                        first(at, &headers, |header, direction| {
                            context_eps().protect(&message.2, header, direction).ok()
                        })
                    };
                Self::Eps(messages.iter().enumerate().filter_map(protected).collect())
            }
        }
    }

    /// `protect` and `unprotect` on the messages that a context protects;
    /// none for an input without such a message.
    pub(crate) fn operations<'a>(&'a self, messages: &'a Messages) -> Vec<Operation<'a>> {
        match (self, messages) {
            (Self::FiveGs(protected), Messages::FiveGs(messages)) if !protected.is_empty() => {
                let count = protected.len();
                vec![
                    prepared("protect", count, move |at| {
                        let (mut context, protected) = (context_5gs(), &protected[at]);
                        let message = black_box(&messages[protected.at].1);
                        move || {
                            done(context.protect(message, protected.header, protected.direction))
                        }
                    }),
                    prepared("unprotect", count, move |at| {
                        let (mut context, protected) = (context_5gs(), &protected[at]);
                        let wire = black_box(&protected.wire);
                        move || done(context.unprotect(wire, protected.direction))
                    }),
                ]
            }
            (Self::Eps(protected), Messages::Eps(messages)) if !protected.is_empty() => {
                let count = protected.len();
                vec![
                    prepared("protect", count, move |at| {
                        let (mut context, protected) = (context_eps(), &protected[at]);
                        let message = black_box(&messages[protected.at].2);
                        move || {
                            done(context.protect(message, protected.header, protected.direction))
                        }
                    }),
                    prepared("unprotect", count, move |at| {
                        let (mut context, protected) = (context_eps(), &protected[at]);
                        let wire = black_box(&protected.wire);
                        move || done(context.unprotect(wire, protected.direction))
                    }),
                ]
            }
            _ => Vec::new(),
        }
    }
}
