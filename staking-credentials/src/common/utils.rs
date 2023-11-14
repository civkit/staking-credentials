// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT> or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

/// A privacy-preserving authenticator that is used for authorization.

use bitcoin::{Txid, MerkleBlock};

pub struct Credentials(pub [u8; 32]);

impl Credentials {
	pub fn serialize(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.resize(32, 0);
		vec.copy_from_slice(&self.0);
		vec
	}
}

#[derive(Debug)]
pub enum Proof {
	Txid(Txid),
	MerkleBlock(MerkleBlock),
}

#[cfg(test)]
mod test {
	use crate::common::utils::Credentials;

	#[test]
	fn test_credentials_serialize() {
		let credentials = Credentials([0, 1, 2 , 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]);
		credentials.serialize();
	}
}
