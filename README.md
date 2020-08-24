# rtpcap: A Tool for RTP Trace Analysis

By [Chema Gonzalez](https://github.com/chemag), 2020-08-24


# Rationale
This document describes rtpcap, a tool for RTP trace analysis. The idea under rtpcap is to get an understanding of video, audio, network, and even performance issues for video-conference (VC) clients based on their network traffic. Network traffic is the main interface of these clients during a VC. In particular, almost all VC systems use RTP, so an RTP parser is the right approach. And while almost all VC systems encrypt the RTP payloads, there is enough data in the RTP headers to get a good understanding of the media dynamics.

We show some examples of the operation, and some of the analysis types.

Discussion:

* pro: does not need instrumenting the VC system
* pro: supports any VC system that uses RTP (almost all)
* pro: modular architecture (allows easy extensions)
* implemented as a python script on top of tshark
* unix principle: only extract timeseries data from the packet trace
* works together with [plotty](https://github.com/chemag/plotty)

Open questions:
* how to put rtpcap and plotty together more easily?


# Examples

[todo]


# Requirements
Requires a functioning `tshark` binary. Works with
* Linux
* Mac OS X



See the [CONTRIBUTING](CONTRIBUTING.md) file for how to help out.

## License
rtpcap is BSD licensed, as found in the [LICENSE](LICENSE) file.

