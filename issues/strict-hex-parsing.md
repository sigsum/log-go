# Strict hex parsing
reported by: rgdd

Our API spec requires use of lower-case hex.  The `encoding/hex` library already
outputs lower-case hex, but it also parses upper-case hex.  Needs to be fixed.
