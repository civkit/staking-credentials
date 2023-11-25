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

use std::ops::Deref;
use std::io;
use std::io::Read;
use core::fmt::Write;

#[derive(Debug)]
pub enum MsgError {
	MsgType,
	ProofDeser(bitcoin::consensus::encode::Error),
	MaxLength,
	IoError(io::Error),
}


pub trait Encodable {
	fn encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, MsgError>;
}

pub trait Decodable: Sized {
	fn decode<R: io::Read + ?Sized>(data: &mut R) -> Result<Self, MsgError>;
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
	fn encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, MsgError> {

		let mut len = 0;
		// "staking credentials" msg type"
		let msg_type = 0;
		len += w.write(&[msg_type]).unwrap();

		//TODO: add a byte for the type of proofs ?
		let serialized_proof = match &self.proof {
			Proof::Txid(txid) => { serialize(&txid) },
			Proof::MerkleBlock(mb) => { serialize(&mb) },
		};
		let size_bytes = serialized_proof.len().to_be_bytes();

		len += w.write(&size_bytes).unwrap();
		len += w.write(&serialized_proof).unwrap();

		let size_bytes = self.credentials.len().to_be_bytes();
		len += w.write(&size_bytes).unwrap();

		for c in &self.credentials {
			let credentials_bytes = c.serialize();
			len += w.write(&credentials_bytes).unwrap();
		}
		Ok(len)
	}
}

impl Decodable for CredentialAuthenticationPayload {
	fn decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, MsgError> {

		let mut buf_msg_type_byte = [0; 1];
		reader.read_exact(&mut buf_msg_type_byte);

		if buf_msg_type_byte[0] != 0 { return Err(MsgError::MsgType); }

		let mut buf_sizes_bytes = [0; 8];
		reader.read_exact(&mut buf_sizes_bytes);

		let value = usize::from_be_bytes(buf_sizes_bytes);

		// Be more robust on max size of merkle block
		if value > 10_000 { return Err(MsgError::MaxLength) };

		let mut buf_proof_bytes = Vec::new();
		buf_proof_bytes.resize(value, 0);
		reader.read_exact(&mut buf_proof_bytes);


		let mb: Result<MerkleBlock, bitcoin::consensus::encode::Error> = bitcoin::consensus::deserialize(&buf_proof_bytes);
		let mb_proof = match mb {
			Ok(mb) => { Proof::MerkleBlock(mb) },
			Err(err) => { return Err(MsgError::ProofDeser(err)); },
		};

		let mut buf_sizes_bytes = [0; 8];
		reader.read_exact(&mut buf_sizes_bytes);

		let value = usize::from_be_bytes(buf_sizes_bytes);

		let mut credentials = Vec::with_capacity(value);

		for i in 0..value {
			let mut buf_credential = [0; 32];
			reader.read_exact(&mut buf_credential);
			credentials.push(Credentials(buf_credential));
		}

		Ok(CredentialAuthenticationPayload {
			proof: mb_proof,
			credentials: credentials,
		})
	}
}

impl Encodable for CredentialAuthenticationResult {
	fn encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, MsgError> {
		let mut len = 0;
		let size_bytes = self.signatures.len().to_be_bytes();
		let size_len_byte = size_bytes.len() as u8;
		len += w.write(&[size_len_byte]).unwrap();
		len += w.write(&size_bytes).unwrap();
		for sig in &self.signatures {
			len += w.write(&sig.serialize_compact()).unwrap();
		}
		Ok(len)
	}
}

impl Decodable for CredentialAuthenticationResult {
	fn decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, MsgError> {
		let mut buf_size_len_byte = [0; 1];
		reader.read_exact(&mut buf_size_len_byte);

		//if data.len() !=  { return Err(()); }
		Err(MsgError::MsgType)
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
	use bitcoin::network::message::NetworkMessage::MerkleBlock;
	use bitcoin::consensus::Encodable;
	use bitcoin::hashes::{Hash, sha256, HashEngine};
	use bitcoin::secp256k1::{ecdsa, Message, PublicKey, Secp256k1, SecretKey};

	use crate::common::utils::{Credentials, Proof};
	use crate::common::msgs::*;
	use crate::common::msgs::Encodable as CredentialEncodable;

	use std::str::FromStr;
	use std::iter::zip;

	#[test]
	fn test_credential_authentication() {
		let mb_bytes = Vec::from_hex("01000000ba8b9cda965dd8e536670f9ddec10e53aab14b20bacad27b913719\
		0000000000190760b278fe7b8565fda3b968b918d5fd997f993b23674c0af3b6fde300b38f33a5914ce6ed5b\
		1b01e32f570200000002252bf9d75c4f481ebb6278d708257d1f12beb6dd30301d26c623f789b2ba6fc0e2d3\
		2adb5f8ca820731dff234a84e78ec30bce4ec69dbd562d0b2b8266bf4e5a0105").unwrap();
		let mb = bitcoin::consensus::deserialize(&mb_bytes).unwrap();
		let proof = Proof::MerkleBlock(mb);
		let credentials = vec![Credentials([16;32]), Credentials([20;32]), Credentials([24;32])];

		let mut buffer = vec![];
		let mut credential_authentication = CredentialAuthenticationPayload::new(proof, credentials);
		credential_authentication.encode(&mut buffer);
		let copy_bytes = buffer.clone();
		let hex_string = buffer.to_hex();
		let mut bytes = Vec::from_hex(&hex_string).unwrap();
		assert_eq!(copy_bytes, bytes);
		let mut credential_authentication_decode = CredentialAuthenticationPayload::decode(&mut bytes.deref()).unwrap();

		assert_eq!(credential_authentication.proof, credential_authentication_decode.proof);
		assert_eq!(credential_authentication.credentials.len(), credential_authentication_decode.credentials.len());
		let mut credentials_iter = zip(credential_authentication.credentials, credential_authentication_decode.credentials);
	
		for (left, right) in credentials_iter {
			assert_eq!(left, right);
		}

		// We test serialization deserialization of regtest merkle block.
		let bytes = Vec::from_hex("0000002006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f441a4f6750cce9e7b80d22a314d107abd8a50bf7b9bd60cc74acba1260b4df487c584d65ffff7f20000000000100000001441a4f6750cce9e7b80d22a314d107abd8a50bf7b9bd60cc74acba1260b4df480101000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
		if let Err(_) = CredentialAuthenticationPayload::decode(&mut bytes.deref()) {}
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
