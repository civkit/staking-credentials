// This file is Copyright its original authors, visibile in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.


/// Configuration we set when applicable.
#[derive(Copy, Clone, Debug)]
pub struct RiskEngineConfig {}

impl Default for RiskEngineConfig {
	fn default() -> RiskEngineConfig {
		RiskEngineConfig {}
	}
}

/// Manager which stores asset proofs and generate credentials generation requests.
/// TODO: should the authenticated credentials be considered as valuable digital
/// collectibles like bitcoin secret keys and as such firewall behind signer interface ?
pub struct CommitManager {
	default_configuration: RiskEngineConfig,
}

impl CommitManager {
	pub fn new() -> Self {
		CommitManager {
			default_configuration: RiskEngineConfig::default(),
		}
	}

	pub fn register_collateral(fresh_collaterals: Vec<CollateralAsset>) {

		for collateral in fresh_collaterals {
			match {
				CollateralAsset::OnchainPayment => { self.fresh_onchain_txids },
				CollateralAsset::OffchainPayment => { self.fresh_invoivec_hashes },
			}
		}

		//TODO: error if already existent
	}

	pub fn get_credentials_authentication_request() -> Result<RequestCredentialsAuthentication, StakingCredentialsIssuanceError> {
	
	}
}
