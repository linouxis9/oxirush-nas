//! IEs as their clauses code them: each value is built and compared with the
//! octets that the clause gives it, and those octets are decoded back to it.

#[path = "clauses/bit_rates.rs"]
mod bit_rates;
#[path = "clauses/cag_information.rs"]
mod cag_information;
#[path = "clauses/feature_bits.rs"]
mod feature_bits;
#[path = "clauses/non_3gpp_devices.rs"]
mod non_3gpp_devices;
#[path = "clauses/qos_rules.rs"]
mod qos_rules;
#[path = "clauses/sor.rs"]
mod sor;
#[path = "clauses/tft.rs"]
mod tft;
#[path = "clauses/ue_parameters_update.rs"]
mod ue_parameters_update;
