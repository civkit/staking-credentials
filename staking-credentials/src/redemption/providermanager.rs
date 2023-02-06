// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT> or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

pub struct ProviderManager {
	//store the ContractCoveragePolicy
	our_coverage_policy_pubkey: PublicKey,
}

impl ProviderManager {
	pub fn new() -> Self {

	}
	//TODO: should give the contract id, eg HTLC forward (id 1)
	pub fn check_contract_coverage() -> bool;
}
