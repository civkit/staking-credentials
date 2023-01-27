// This file is CopyRight its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT> or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! The IssuanceManager is an implementation of Staking Credentials's Issuer
//! entity, an entity that commit a scarce asset to redeem an authenticated
//! Credential from an Issuer.
//!
//! This component stores key material, validate asset proofs and counter-sign
//! blinded credentials. This is the source of authority for the CredentialPolicy
//! gossip message.
//!
//! The CredentialPolicy parameters can be selected in function of the results
//! from RiskMonitor.

use bitcoin::secp256k1::Secp256k1;
use bitcoin::secp256k1::PublicKey;

use risk_monitor::RiskMonitor;

use crate::msgs;
use crate::msgs::CollateralAsset;
use crate::commitmanager::RiskEngineConfig;

pub struct IssuanceManager<R: Deref, V: Deref>
where
    	R::Target: RiskMonitor,
	V::Target: AssetProofVerifier,
{
	default_configuration: RiskEngineConfig,

	risk_monitor: R,
	verifier: V,

	best_block: u32,

	secp_ctx: Secp256k1<secp256k1::All>,
	our_credential_policy_pubkey: PublicKey,
}

impl<R: Deref, V: Deref> IssuanceManager<R, V>
where
    	R::Target: RiskMonitor,
	V::Target: AssetProofVerifier,
{
	/// Constructs a new IssuanceManager to manage credentials authentication.
	pub fn new(risk_monitor: R, verifier: V, our_credential_policy_seckey: SecretKey) -> Self {
		let mut secp_ctx = Secp256k1::new();
		let our_credential_policy_pubkey = PublicKey::from_secret_key(&secp_ctx, our_credential_policy_seckey);
		IssuanceManager {
			default_configuration: RiskEngineConfig::default(),

			risk_monitor,
			verifier,

			best_block,

			secp_ctx,
			our_credential_policy_pubkey,
		}
	}

	/// Generate a CredentialPolicy to be consumed by Committer, Client and Contract Provider
	/// entities.
	pub fn get_credential_policy(&self) -> CredentialPolicy {
	}

	pub fn commit_asset(&mut self, msg: &msgs::ReplyAsset) -> Result<ReplyAsset, StakingCredentialsIssuanceError> {

		if !self.verifier.verify_proofs() {
			return Err();
		}
	}
}

/// A trait which should be implemented to provide asset collateral verification to the IssuanceManager
///
/// This can connect to bitcoind's `getreceivedbyaddress` or a LDK's `PaymentClaimable` events store.
pub trait AssetProofsVerifier {
	fn verify_proofs(asset_proofs: <CollateralAsset>) -> bool;
}
