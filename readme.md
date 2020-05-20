# Distributed signature prototype

- Keygen phase: an EdDSA private key is split between several peers
- Signing phase: a subset of peers signs the message with their secret share
- Final signature is reconstructed from peer signature pieces

Used algorithms are described in [Threshold Signatures Using Ed25519 and Ed448](https://tools.ietf.org/id/draft-hallambaker-threshold-sigs-00.html)

- Aggregate (unanimous) signature
- Threshold signature
