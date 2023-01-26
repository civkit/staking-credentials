// This file is Copyright its original authors, visibile in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Wire messages, traits representing wire message handlers, and a few error types live here.
//!
//! In the normal issuance sequence, the default CommitManager and IssuanceManager implems can
//! be used. If you would like to re-implement your own custom credentials authentication flows
//! with non-standard state machines the messages can be useful.

use bitcoin_hashes::sha256;

use bitcoin::secp256k1::PublicKey;
use bitcoin::secp256k1::ecdsa::Signature;

use bitcoin::hash_types::Txid;

use core::fmt::Debug;

/// A request_credentials_authentication message to be sent to start the credentials authentication dance.
/// Note if the issuance is in "reward" mode, a subset of the credentials can be stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestCredentialsAuthentication {
	/// A proof of asset as a base collateral for the credentials.
	pub asset_proof: <CollateralAsset>,
	/// A list of unsigned blinded credentials.
	pub blinded_credentials: Vec<BlindedCredentials>
	//TODO: blinded route https://github.com/lightning/bolts/pull/765
}

/// The base collaterals backing up the authentication of credentials.
/// Note, an Issuenr entity is not mandated to support of all of them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CollateralAsset {
	/// The txid of an on-chain payment.
	OnchainPayment {
		/// A Bitcoin transaction txid.
		txid: Txid,
	},
	/// The invoice hash of a Lightning off-chain payment.
	OffchainPayment {
		/// A BOLT11 raw invoice hash.
		invoice_hash: [u8; 32],
	},
}

/// The type of blinded credentials. The size of the credential unit
/// can vary in function of the underlying cryptosystems.
pub enum BlindedCredentials {
	/// The basic 32-byte string.
	BasicCredential {
		/// A 32-byte data string.
		data: [u8, 32],
	},
}

/// A reply_asset message to end the credentials authentication dance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplyAsset {
	/// The issuance pubkey.
	pub issuance_pubkey: PublicKey
	/// A list of signed blinded credentials.
	pub blinded_credentials: Vec<BlindedCredentials>,
	/// A list of credential signatures.
	pub credentials_signature: Signature,
}

/// An error for failure to process messages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StakingCredentialsIssuanceError {
	pub err: String,
	pub action: ErrorAction,
}

/// Used to put an error message in StakingCredentialsIssuanceError.
#[derive(Clone, Debug)]
pub enum ErrorAction {
	/// The peer did something harmless that we weren't able to process, just log and ignore.
	IgnoreError,
}
