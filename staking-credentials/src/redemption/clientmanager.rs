// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT> or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

pub struct ClientManager<D: Deref>
where
	D::Target: CredentialsDealer,
{
	credentials_dealer: D,

	onion_messenger: OnionMessenger,
}

impl<D: Deref> ClientManager<D>
where
    	D::Target: CredentialsDealer,
{
	pub fn new(credentials_dealder: D, onion_messenger: OnionMessenger) -> Self {
		ClientManager {
			credentials_dealer: D,
			onion_messenger,
		}
	}

	pub send_credentials(&self, node_id: PublicKey) {
		self.onion_messenger.send_onion_message();
	}

	pub fetch_credentials() {

	}

	pub get_credentials_back(&self) {

	}
}

/// A trait which should be implemented to provide unblinded credentials to the
/// ClientManager. If the deployment type is "self-hosted", the CredentialsProvider
/// should be the ClientManager, otherwise a communication channel should be established
/// with an unblinded credential dealer (e.g a LSP).
pub trait CredentialsDealer {
	fn fetch_credentials() -> Vec<UnblindedCredentials> {

	}
}
