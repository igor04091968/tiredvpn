# REALITY single-flight strategy

Based on the TLS handshake burst measurements in https://habr.com/ru/articles/1044396/ . The source reports an observed heuristic, not a stable specification. This candidate tests whether avoiding closely spaced TLS handshakes across *all* donor SNI helps on the Rostelecom path.

Select with `-strategy reality_singleflight`. The variant uses the same REALITY wire format, fingerprint and server configuration as `reality`, so the existing server already accepts it. Authentication and data framing are unchanged. It allows one handshake at a time across donor names, with 450–600 ms between starts. The original `-strategy reality` retains its per-SNI limit of two and 250–500 ms spacing. The variant has low automatic priority; explicit selection is intended for lab A/B checks. It adds latency when new concurrent connections are opened.

The 2026-10-07 canary test used gw2 TCP/UDP 13443. All 23 compatible strategy checks passed, including this ID. Both `reality` and `reality_singleflight` returned HTTP 200 for Telegram, WhatsApp and YouTube through the canary. Success proves compatibility and data delivery on that test port. It does not prove better reliability under an active block, or behavior on the production port 12443.

The maintainer also reports successful connections and traffic delivery with
`reality_singleflight` on MTS, Rostelecom, and TTK. The strategy is working on
those tested networks. These field checks do not compare its success rate with
the standard `reality` strategy during a reproducible block.

No current TiredVPN failure has been reproduced on this path; both variants reach the three selected services. To test the benefit, repeat equal-size A/B runs on the same server and port during an actual baseline handshake failure, recording first TLS data-packet times and successful tunneled requests. If the variant fails equally often or is merely slower, the hypothesis is not supported.
