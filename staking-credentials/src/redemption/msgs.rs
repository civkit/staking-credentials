// This file is Copyright its original authors, visibile in version control
// history.
//
// This file is licensed under the Apache license, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT> or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Wire messages, traits representing wire message handlers, and a few error types
//! live here.
//!
//! In the normal issuance sequence, the default ClientManager and ProviderManager impems
//! can be used. If you would like to re-implement your own custom credentials redemption
//! flows with non-standard state machines the message can be useful.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedeemCredentials {
	pub unblinded_credentials: Vec<UnblindedCredentials>,
	pub credentials_signature: Vec<Signature>,
	pub reward_blinded_credentials: Vec<BlindedCredentials>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnblindedCredentials {
	BasicUnblindedCredentials {
		data: [u8, 32],
	},
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StakingCredentialsRedemptionError {
	pub err: String,
	pub action: ErrorAction,
}

#[derive(Clone, Debug)]
pub enum ErrorAction {
	IgnoreError,
}
