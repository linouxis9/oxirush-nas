# oxirush-nas

[![Crates.io](https://img.shields.io/crates/v/oxirush-nas.svg)](https://crates.io/crates/oxirush-nas)
[![Documentation](https://docs.rs/oxirush-nas/badge.svg)](https://docs.rs/oxirush-nas)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

> ⚠️ **Note**: This library is currently in active development and not all features may be available.

A fast, memory-safe library for encoding and decoding 5G Non-Access Stratum (NAS) messages, written in Rust.

Part of the future [OxiRush](https://github.com/linouxis9/oxirush) project - a comprehensive next-generation 5G Core Network testing framework.

## Overview

`oxirush-nas` provides a robust implementation for working with 5G NAS protocol messages and IEs, which are used for the communication between the User Equipment (UE) and the 5G Core Network.

## Features

- **Complete Protocol Support**: Full implementation of 5G NAS protocol as defined in 3GPP TS 24.501
- **High Performance**: Optimized for speed and minimal memory usage
- **Type Safety**: Leverages Rust's type system to prevent protocol errors at compile time

## Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
oxirush-nas = "0.1.1"
```

## Usage Examples

### Basic Message Decoding and Encoding

```rust
use oxirush_nas::{decode_nas_5gs_message, encode_nas_5gs_message, Nas5gsMessage};

#[test]
fn test() -> Result<()> {
    // Example NAS message bytes (Registration Request)
    let nas_bytes = hex::decode("7e004179000d0199f9070000000000000010022e08a020000000000000")?;
    
    // Decode the message
    let parsed_message = decode_nas_5gs_message(&nas_bytes)?;
    
    // Print message details
    match &parsed_message {
        Nas5gsMessage::Gmm(header, message) => {
            println!("Message Type: {:?}", header.message_type);

            match &message {
                Nas5gmmMessage::RegistrationRequest(reg_request) =>{
                    println!("Registration Type Value: {}", reg_request.Fgs_registration_type.value);
                    println!("Mobile Identity Length: {}", reg_request.Fgs_mobile_identity.length);
                    
                    if let Some(sec_cap) = &reg_request.ue_security_capability {
                        println!("UE Security Capability: {:?}", sec_cap.value);
                    }
                },
                _ =>  println!("Not a RegistrationRequest message"),
            }
        },
        _ => println!("Not a GMM message"),
    }
    
    // Re-encode the message
    let encoded_message = encode_nas_5gs_message(&parsed_message)?;
    
    // Verify encoding matches the original
    println!("Encoding matches original: {}", nas_bytes == encoded_message);

    Ok(())
}
```
## Documentation

For more detailed documentation, see:

- [oxirush-nas's API Reference](https://docs.rs/oxirush-nas)
- [3GPP TS 24.501 Specification](https://www.3gpp.org/DynaReport/24501.htm)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please make sure your code passes all tests and adheres to the project's coding style.

### Developer Certificate of Origin (DCO)

By contributing to this project, you agree to the [Developer Certificate of Origin (DCO)](https://developercertificate.org/). This means that you have the right to submit your contributions and you agree to license them according to the project's license.

All commits should be signed-off with `git commit -s` to indicate your agreement to the DCO.

## License

Copyright 2025 Valentin D'Emmanuele

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## Acknowledgements

OxiRush is inspired by the [PacketRusher](https://github.com/HewlettPackard/PacketRusher) project, reimplemented in Rust for improved performance and safety.