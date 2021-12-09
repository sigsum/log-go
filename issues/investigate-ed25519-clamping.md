**Title:** Investigate Ed25519 clamping behavior</br>
**Date:** 2021-12-09 </br>

# Summary
Ed25519 signatures have three bits that should be zero due to clamping.  What
happens when verifying a signature that has these three bits set to something
else?  Sigsum requires that such a signature is rejected.

# Description
First confirm that Ed25519 signatures are clamped as described in the summary,
then investigate how `Verify()` is implemented in `"crypto/ed25519"`.  The
assumed sigsum-log-go behavior is that `Verify()` is strict.  In other words, a
signature that is not clamped correctly should be rejected and not "fixed".

If a signature is "fixed" it would be possible to replay add-leaf requests.  A
replay is bad for the log due to overhead.  A replay is also bad for the
legitimate submitter because it eats into their rate limit (DoS vector).

The following part of Go's implementation might be a good place to start:
- https://cs.opensource.google/go/go/+/refs/tags/go1.16.4:src/crypto/ed25519/ed25519.go;l=208
