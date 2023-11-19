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
//!
//! Serialization methods are from rust-bitcoin libraries, to ensure compatibility
//! with bitcoin structs from there.

use bitcoin::consensus::serialize;
use bitcoin::secp256k1::PublicKey;
use bitcoin::secp256k1::ecdsa::Signature;

use bitcoin::MerkleBlock;

use crate::common::utils::{Credentials, Proof};

use std::io;
use core::fmt::Write;

pub trait Encodable {
	fn encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error>;
}

pub trait Decodable: Sized {
	fn decode(data: &[u8]) -> Result<Self, ()>;
}

pub trait ToHex {
	fn to_hex(&self) -> String;
}

pub trait FromHex: Sized {
	fn from_byte_iter<I>(iter: I) -> Result<Self, ()>
	where
	    I: Iterator<Item = Result<u8, ()>> + ExactSizeIterator + DoubleEndedIterator;

	fn from_hex(s: &str) -> Result<Self, ()> { Self::from_byte_iter(HexIterator::new(s)?) }
}

pub struct HexIterator<'a> {
	iter: std::str::Bytes<'a>,
}

impl <'a> HexIterator<'a> {
	pub fn new(s: &'a str) -> Result<HexIterator<'a>, ()> {
		if s.len() % 2 != 0 {
			Err(())
		} else {
			Ok(HexIterator { iter: s.bytes() })
		}
	}
}

fn chars_to_hex(hi: u8, lo: u8) -> Result<u8, ()> {
	let hih = (hi as char).to_digit(16).ok_or(())?;
	let loh = (lo as char).to_digit(16).ok_or(())?;

	let ret = (hih << 4) + loh;
	Ok(ret as u8)
}

impl<'a> Iterator for HexIterator<'a> {
	type Item = Result<u8, ()>;

	fn next(&mut self) -> Option<Result<u8, ()>> {
		let hi = self.iter.next()?;
		let lo = self.iter.next().unwrap();
		Some(chars_to_hex(hi, lo))
	}

	fn size_hint(&self) -> (usize, Option<usize>) {
		let (min, max) = self.iter.size_hint();
		(min / 2, max.map(|x| x / 2))
	}
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

impl ToHex for [u8] {
	fn to_hex(&self) -> String {
		let mut ret = String::with_capacity(2 * self.len());
		for ch in self {
			write!(ret, "{:02x}", ch).expect("writing to string");
		}
		ret
	}
}

impl<'a> DoubleEndedIterator for HexIterator<'a> {
	fn next_back(&mut self) -> Option<Result<u8, ()>> {
		let lo = self.iter.next_back()?;
		let hi = self.iter.next_back().unwrap();
		Some(chars_to_hex(hi, lo))
	}
}

impl<'a> ExactSizeIterator for HexIterator<'a> {}

impl FromHex for Vec<u8> {
	fn from_byte_iter<I>(iter: I) -> Result<Self, ()>
	where
	    I: Iterator<Item = Result<u8, ()>> + ExactSizeIterator + DoubleEndedIterator,
	{
		iter.collect()
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
	use crate::common::msgs::*;
	use crate::common::msgs::Encodable as CredentialEncodable;

	use std::str::FromStr;

	#[test]
	fn test_credential_authentication() {
		let bytes = [32;32];
		let mut enc = Txid::engine();
		enc.input(&bytes);
		let txid = Txid::from_engine(enc);

		let proof = Proof::Txid(txid);
		let credentials = vec![Credentials([16;32])];

		let mut buffer = vec![];
		let mut credential_authentication = CredentialAuthenticationPayload::new(proof, credentials);
		credential_authentication.encode(&mut buffer);
		let copy_bytes = buffer.clone();
		let hex_string = buffer.to_hex();
		let bytes = Vec::from_hex(&hex_string).unwrap();
		assert_eq!(copy_bytes, bytes);
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

	#[test]
	fn test_credential_policy() {

		let timestamp = 100;
		let issuance_pubkey = PublicKey::from_str("032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af").unwrap();
		let asset_features = Vec::new();
		let asset_proof_features = AssetProofFeatures::new(asset_features);
		let credential_features = Vec::new();
		let credential_proof_features = CredentialsFeatures::new(credential_features);
		let asset_to_credential = 100;
		let expiration_height = 100;

		let unsigned_credential_policy = UnsignedCredentialPolicy {
			timestamp,
			issuance_pubkey,
			asset_proof: asset_proof_features,
			credentials: credential_proof_features,
			asset_to_credential: 100,
			expiration_height: expiration_height,
		};

		let secp_ctx = Secp256k1::new();
		let seckey = [
			59, 148, 11, 85, 134, 130, 61, 253, 2, 174, 59, 70, 27, 180, 51, 107, 94, 203, 174, 253,
			102, 39, 170, 146, 46, 252, 4, 143, 236, 12, 136, 28,
		];
		let seckey = SecretKey::from_slice(&seckey).unwrap();

		//TODO: unsigned_credential_policy.encode();
		let msg = b"test";
		let hash_msg = sha256::Hash::hash(msg);
		let sighash = Message::from_slice(&hash_msg.as_ref()).unwrap();
		let credential_policy_sig = secp_ctx.sign_ecdsa(&sighash, &seckey);

		let credential_policy = CredentialPolicy {
			signature: credential_policy_sig,
			contents: unsigned_credential_policy,
		};
	}

	#[test]
	fn test_service_policy() {

		let timestamp = 100;
		let credential_pubkey = PublicKey::from_str("032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af").unwrap();
		let credential_issuers = vec![credential_pubkey];
		let service_ids = vec![100];
		let credentials_to_service = vec![30];
		let expiration_height = 20;

		let unsigned_service_policy = UnsignedServicePolicy {
			timestamp,
			credential_issuers,
			service_ids,
			credentials_to_service,
			expiration_height,
		};

		let secp_ctx = Secp256k1::new();
		let seckey = [
			59, 148, 11, 85, 134, 130, 61, 253, 2, 174, 59, 70, 27, 180, 51, 107, 94, 203, 174, 253,
			102, 39, 170, 146, 46, 252, 4, 143, 236, 12, 136, 28,
		];
		let seckey = SecretKey::from_slice(&seckey).unwrap();

		//TODO: unsigned_service_policy.encode();
		let msg = b"test";
		let hash_msg = sha256::Hash::hash(msg);
		let sighash = Message::from_slice(&hash_msg.as_ref()).unwrap();
		let service_policy_sig = secp_ctx.sign_ecdsa(&sighash, &seckey);

		let service_policy = ServicePolicy {
			signature: service_policy_sig,
			contents: unsigned_service_policy,
		};
	}
}
