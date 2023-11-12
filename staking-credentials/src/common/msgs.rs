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

use bitcoin::consensus::serialize;
use bitcoin::secp256k1::PublicKey;
use bitcoin::secp256k1::ecdsa::Signature;

use bitcoin::MerkleBlock;

use crate::common::utils::{Credentials, Proof};

use std::io;

pub trait Encodable {
	fn encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error>;
}

pub trait Decodable: Sized {
	fn decode(data: &[u8]) -> Result<Self, ()>;
}

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
	pub fn new(proof: Proof, credentials: Vec<Credentials>) -> Self {
		CredentialAuthenticationPayload {
			proof,
			credentials,
		}
	}
}

impl Encodable for CredentialAuthenticationPayload {
	fn encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
		let mut len = match &self.proof {
			Proof::Txid(txid) => { w.write(&serialize(&txid))? },
			Proof::MerkleBlock(mb) => { w.write(&serialize(&mb))? },
		};
		for c in &self.credentials {
			len += w.write(&c.serialize())?;
		}
		Ok(len)
	}
}

impl Decodable for CredentialAuthenticationPayload {
	fn decode(data: &[u8]) -> Result<Self, ()> {
		let mb: Result<MerkleBlock, bitcoin::consensus::encode::Error> = bitcoin::consensus::deserialize(&data);
		if let Ok(mb) = mb {
			let proof = Proof::MerkleBlock(mb);
			//TODO: deserialize credentials
			return Ok(CredentialAuthenticationPayload {
				proof,
				credentials: vec![],
			})
		}
		return Err(());
	}
}

/// A credential authentication result sent by a peer.
pub struct CredentialAuthenticationResult {
	//TODO: do we need to send back credentials, bandwidth savings by agreeing on ordering ?
	pub signatures: Vec<Signature>,
}

impl CredentialAuthenticationResult {
	pub fn new(signatures: Vec<Signature>) -> Self {
		CredentialAuthenticationResult {
			signatures,
		}
	}
}

/// A service deliverance request attached with unblinded authenticated credential sent by a peer.
pub struct ServiceDeliveranceRequest {
	pub credentials: Vec<Credentials>,
	pub signatures: Vec<Signature>,
	pub service_id: u64,
	pub commitment_sig: Signature,
}

impl ServiceDeliveranceRequest {
	pub fn new(credentials: Vec<Credentials>, signatures: Vec<Signature>, service_id: u64, commitment_sig: Signature) -> Self {
		ServiceDeliveranceRequest {
			credentials,
			signatures,
			service_id,
			commitment_sig
		}
	}
}

/// A service deliverance result sent by a peer.
pub struct ServiceDeliveranceResult {
	pub service_id: u64,
	pub ret: bool,
	pub reason: Vec<u8>,
}

impl ServiceDeliveranceResult {
	pub fn new(service_id: u64, ret: bool, reason: Vec<u8>) -> Self {
		ServiceDeliveranceResult {
			service_id,
			ret,
			reason
		}
	}
}

#[cfg(test)]
mod test {
	use bitcoin::Txid;
	use bitcoin::consensus::Encodable;
	use bitcoin::hashes::{Hash, sha256, HashEngine};
	use bitcoin::secp256k1::{ecdsa, Message, PublicKey, Secp256k1, SecretKey};

	use crate::common::utils::{Credentials, Proof};
	use crate::common::msgs::{CredentialAuthenticationPayload, CredentialAuthenticationResult, ServiceDeliveranceRequest, ServiceDeliveranceResult};

	#[test]
	fn test_credential_authentication() {
		let bytes = [32;32];
		let mut enc = Txid::engine();
		enc.input(&bytes);
		let txid = Txid::from_engine(enc);

		let proof = Proof::Txid(txid);
		let credentials = vec![Credentials([16;32])];

		let mut credential_authentication = CredentialAuthenticationPayload::new(proof, credentials);
		//credential_authentication.encode();
	}

	#[test]
	fn test_credential_result() {
		let signatures = vec![];

		let mut credential_authentication_result = CredentialAuthenticationResult::new(signatures);
	}

	#[test]
	fn test_service_deliverance_request() {
		let credentials = vec![];
		let signatures = vec![];
		let service_id = 0;

		let secp = Secp256k1::new();

		let msg = b"This is some message";

		let seckey = [
			59, 148, 11, 85, 134, 130, 61, 253, 2, 174, 59, 70, 27, 180, 51, 107, 94, 203, 174, 253,
			102, 39, 170, 146, 46, 252, 4, 143, 236, 12, 136, 28,
		];

		let hash_msg = sha256::Hash::hash(msg);
		let msg = Message::from_slice(hash_msg.as_ref()).unwrap();
		let seckey = SecretKey::from_slice(&seckey).unwrap();

		let commitment_sig = secp.sign_ecdsa(&msg, &seckey);

		let mut service_deliverance_request = ServiceDeliveranceRequest::new(credentials, signatures, service_id, commitment_sig);
	}

	#[test]
	fn test_service_deliverance_result() {
		let service_id = 0;
		let ret = false;
		let reason = vec![];

		let mut service_deliverance_result = ServiceDeliveranceResult::new(service_id, ret, reason);
	}

}
