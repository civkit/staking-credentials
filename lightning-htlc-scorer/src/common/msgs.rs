// This file is Copyright its original authors, visibile in version control
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
//! A list of `credentials-to-liquidity-unit` per-Contract-Provider covered can
//! be attached.

use bitcoin::secp256k1::PublicKey;

/// The unsigned part of a credential_policy message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsignedCredentialPolicy {
	pub timestamp: u32,
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

//! A gossip extension message ContractCoveragePolicy to annnounce one per-contract
//! liquidity policy to the rest of the Lightning network.
//!
//! The policy has a timestamp, a list of authoritative credential issuers and
//! a list of contract covered, each with a unique `credential-to-liquidity` ratio.
//!
//! In the future, as we extend the Staking Credentials framework with non-monetary
//! paradigm, a contract coverage could be made of credentials from different paradigm.

/// The unsigned part of a contract_policy message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsignedContractCoveragePolicy {
	pub timestamp: u32,
	pub credential_issuers: Vec<PublicKey>,
	pub contract_covered: Vec<ContractTemplate>, // should have identifier + credential-to-liquidity-unit
	pub expiration_height: u32,
}

/// A contract_policy message to be sent or received from a peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractCoveragePolicy {
	pub signature: Signature,
	pub contents: UnsignedContractCoveragePolicy,
}
