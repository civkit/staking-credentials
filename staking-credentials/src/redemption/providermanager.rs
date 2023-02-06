// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT> or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use bitcoin::secp256k1::PublicKey;

use common::ContractCoveragePolicy,

//TODO: add onion handlers
pub struct ProviderManager {
	contract_coverage_policy: ContractCoveragePolicy,

	credentials_accumulator: HashMap<Sha256, Some()>

	risk_engine: RiskEngine
}

impl ProviderManager {
	pub fn new(contract_coverage_policy: ContractCoveragePolicy) -> Self {
		ProviderManager {
			contract_coverage_policy: ContractCoveragePolicy,
			credentials_accumulator: HashMap::new(),
		}
	}
	//TODO: should give the contract id, eg HTLC forward (id 1)
	pub fn check_contract_coverage() -> bool {
		// should match credential with paired id

		// should mark the credentials as consumed in the accumulator
	}

	pub fn mark_contract_result() {

	}

	pub fn receive_credentials() {
		// should store the blinded path for return
	}

	pub fn get_update_contract_coverage_policy(expiration_height: u32) -> ContractCoveragePolicy {
		// should probe the risk engine	
	}
}
