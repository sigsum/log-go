# Ed25519 clamping behavior
Reported by: rgdd

If I recall correctly an Ed25519 signature has 3 bits that should always be
zero. What happens if any of the 3 bits are not zero during signature
verification? It probably depends on the implementation. I would expect that the
signature is rejected. However, a possible behavior that I would not expect is
that the three bits are zeroed ("fixed").

We need the signature to be rejected; not fixed. Otherwise it is possible to
replay a logged entry several times by enumerating the remaining bit patterns.
Replays are bad for the log (overhead).  Replays are also bad for the legitimate
submitter because it will eat into their rate limit (DoS vector).

It would be great if anyone could:
- Confirm if I recall correctly. And if so, confirm if the behavior of
`crypto/ed25519` is to reject signatures if any of the three bits are set.
- After a quick look this might be the place to understand:
https://cs.opensource.google/go/go/+/refs/tags/go1.16.4:src/crypto/ed25519/ed25519.go;l=208
