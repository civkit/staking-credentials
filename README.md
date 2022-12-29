Staking Credentials
===================

"Not tokens, credentials".

This is an in-progress implementation of the [Staking Credentials](https://lists.linuxfoundation.org/pipermail/lightning-dev/2022-November/003754.html) HTLC risk-management framework
to mitigate against [channel jamming attacks](https://jamming-dev.github.io/book/1-impacts.html) against a Lightning node.

The module aims in priority to be compatible with the Lightning Dev Kit architecture, while
progressively extending support to other Lightning softwares.

DO NOT USE IT WITH REAL MONEY!!! Anyway, this is just a PoC for now, with the code far behind
the protocol draft specification.

License is either Apache-2.0 or MIT, at the option of the user (ie dual-license Apache-2.0
and MIT).
