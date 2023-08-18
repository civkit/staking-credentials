// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT> or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use crate::common::utils::Credentials;
use crate::common::msgs::{AssetProofFeatures, CredentialsFeatures};

pub struct RequesterState {
	asset_flags: AssetProofFeatures,
	credentials_flags: CredentialsFeatures,
}

impl RequesterState {
	pub fn new (asset_flags: AssetProofFeatures, credentials_flags: CredentialsFeatures) -> RequesterState {
		RequesterState {
			asset_flags: asset_flags,
			credentials_flags: credentials_flags,
		}
	}

	pub fn generate_credentials(credentials_quantity: u32) -> Result<Vec<(Credentials)>, ()> {
		//TODO: generate credentials according to issuance policy
		return Err(());
	}
}
