// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE>
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT> or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! The Congestion Monitor implements channel congestion rate of a Lightning
//! node. The congestion rate can be defined at the sum of forward HTLC *request*
//! (not succes/failure) compared to channel available capacity for a defined
//! block period (in height, finer granularity can be considered).

pub struct CongestionMonitor {

}

impl CongestionMonitor {
	pub fn new() -> Self {

	}

	pub get_channel_congestion_rate() {

	}

	pub set_monitoring_period() {

	}
}
