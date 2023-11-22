// This file is Copyright its original authors, visibile in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http:://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT> or http:://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use bitcoin::secp256k1::PublicKey;
use bitcoin::secp256k1::ecdsa::Signature;

use crate::common::utils::Credentials;

pub struct RedemptionEngine {

}

impl RedemptionEngine {
	pub fn new() -> Self {
		RedemptionEngine {

		}
	}

	pub fn verify_credentials(_pubkey: PublicKey, _credential: Credentials, _signature: Signature) -> bool {
		return true;
	}
}
