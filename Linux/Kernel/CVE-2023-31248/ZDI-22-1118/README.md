# ZDI-22-1118

Exploit for [ZDI-22-1118](https://www.zerodayinitiative.com/advisories/ZDI-22-1118/). For Ubuntu `jammy`, kernel version `5.15.0-30-generic`.

This exploit uses `CVE-2022-2078` and `CVE-2022-2586`.

Note that you will need to patch `libnftnl` to be able to overflow `NFTA_SET_DESC_CONCAT`.
