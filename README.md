Staking Credentials
===================

This is a Rust-based framework implements a reputation system aimed at enhancing the resilience of the Lightning Network against channel jamming. Central to this system is the innovative use of "credentials" issued by network routing hops, attached to each Hashed Time-Locked Contract (HTLC) forward request. These credentials are crucial for a reputation algorithm that rewards or penalizes payment senders, promoting efficient channel liquidity management. The system begins with a bootstrap phase involving one-time upfront fees, with subsequent credential distribution evolving based on HTLC traffic. This approach facilitates dynamic HTLC traffic shaping, offering solutions to both malicious and spontaneous jamming. Initially, this framework will be employed to mitigate counterparty risk in Bitcoin financial contracts and to redeem services from paid Nostr relays, such as a CivKit functionary node. The implementation focuses on high-level privacy, user transparency, and network adaptability, contributing to a more robust, flexible, and efficient Lightning Network through a transparent and privacy-preserving reputation mechanism.

This is an in-progress implementation of the [Staking Credentials](https://lists.linuxfoundation.org/pipermail/lightning-dev/2022-November/003754.html) to mitigate counterparty risk in Bitcoin financial contracts or to redeem services
from a paid Nostr relay (e.g a CivKit functionary node).

The module aims in priority to be compatible with the Lightning Dev Kit architecture, while progressively extending support to other Lightning softwares.

DO NOT USE IT WITH REAL MONEY!!! 

License is either Apache-2.0 or MIT, at the option of the user (ie dual-license Apache-2.0 and MIT).
