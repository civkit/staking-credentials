// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT> or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! A gossip extension message CredentialPolicy to announce one's base collateral
//! acceptance and credential issuance policy to the rest of the Lightning network.
//!
//! The policy has a timestamp, a list of accepted asset proofs, a list of accepted
//! credentials, the `asset-to-credential` ratio and the expiration height of
//! credentials if any.
//!
//! A list of `credentials-to-service-unit` per-Provider covered can be attached.

use bitcoin::secp256k1::PublicKey;
use bitcoin::secp256k1::ecdsa::Signature;

use crate::common::utils::{Credentials, Proof};

/// A set of flags bits for scarce assets proofs accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetProofFeatures {
	flags: Vec<u8>,
}

impl AssetProofFeatures {
	pub fn new(flags: Vec<u8>) -> Self {
		AssetProofFeatures { flags }
	}
}

///A set of flags bit for credentials cryptosystems supported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialsFeatures {
	flags: Vec<u8>,
}

impl CredentialsFeatures {
	pub fn new(flags: Vec<u8>) -> Self {
		CredentialsFeatures { flags }
	}
}

/// The unsigned part of a credential_policy message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsignedCredentialPolicy {
	pub timestamp: u32,
	pub issuance_pubkey: PublicKey,
	pub asset_proof: AssetProofFeatures,
	pub credentials: CredentialsFeatures,
	pub asset_to_credential: u32,
	pub expiration_height: u32,
}

/// A credential_policy message to be sent or received from a peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialPolicy {
	pub signature: Signature,
	pub contents: UnsignedCredentialPolicy,
}

/// A gossip extension message ServicePolicy to annnounce one per-service providance policy.
///
/// The policy has a timestamp, a list of authoritative credential issuers and
/// a list of service covered, each with a unique `credentials-to-service` ratio.

/// The unsigned part of a service_policy message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsignedServicePolicy {
	pub timestamp: u32,
	pub credential_issuers: Vec<PublicKey>,
	pub service_ids: Vec<u32>, // should have identifier + credential-to-liquidity-unit
	pub credentials_to_service: Vec<u32>,
	pub expiration_height: u32,
}

/// A service_policy message to be sent or received from a peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServicePolicy {
	pub signature: Signature,
	pub contents: UnsignedServicePolicy,
}

/// A credential authentication request sent by a peer.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CredentialAuthenticationPayload {
	pub proof: Proof,
	pub credentials: Vec<Credentials>,
}

impl CredentialAuthenticationPayload {
	fn new(proof: Proof, credentials: Vec<Credentials>) -> Self {
		CredentialAuthenticationPayload {
			proof,
			credentials,
		}
	}
}

#[cfg(test)]
mod test {
	use bitcoin::Txid;
	use bitcoin::hashes::{Hash, HashEngine};

	use crate::common::utils::{Credentials, Proof};
	use crate::common::msgs::CredentialAuthenticationPayload;

	#[test]
	fn test_credential_authentication() {
		let bytes = [32;32];
		let mut enc = Txid::engine();
		enc.input(&bytes);
		let txid = Txid::from_engine(enc);

		let proof = Proof::Txid(txid);
		let credentials = vec![Credentials([16;32])];

		let mut credential_authentication = CredentialAuthenticationPayload::new(proof, credentials);
	}
}
