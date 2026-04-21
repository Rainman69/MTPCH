"""MTPCH — MTProto Proxy Checker.

A cross-platform command-line tool that performs *real* end-to-end
connection verification of Telegram MTProto (MTProxy) proxies by
executing the obfuscated transport handshake described at
https://core.telegram.org/mtproto/mtproto-transports and then
exchanging a genuine ``req_pq_multi`` / ``resPQ`` handshake with a
Telegram datacenter through the proxy.
"""

__version__ = "1.0.0"
__all__ = ["verifier", "parser", "sources", "output", "cli"]
