// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT> or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use bitcoin::secp256k1::PublicKey;
use bitcoin::secp256k1::ecdsa::Signature;

use crate::common::utils::Credentials;
use crate::common::msgs::{AssetProofFeatures, CredentialsFeatures};

struct IssuerState {
	asset_flags: AssetProofFeatures,
	credentials_flags: CredentialsFeatures,
	issuance_pubkey: PublicKey,
}

impl IssuerState {
	pub fn new(asset_flags: AssetProofFeatures, credentials_flags: CredentialsFeatures, pubkey: PublicKey) -> Self {
		IssuerState {
			asset_flags: asset_flags,
			credentials_flags: credentials_flags,
			issuance_pubkey: pubkey,
		}
	}

	pub fn verify_asset_proofs() -> Result<Vec<(Credentials, Signature)>, ()> {
		//TODO: verify if credential is supported
		//TODO: generate signature
		return Err(());
	}
}
