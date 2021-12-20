**Title:** Refactor pkg/state/single.go </br>
**Date:** 2021-12-20 </br>

# Summary
Remove unwanted dependencies and resolve minor TODOs in `pkg/state/single.go`.

# Description
Some refactoring is needed in `pkg/state/single.go`.  In more detail, the
following dependencies are overkill and should ideally be removed:
- "github.com/google/certificate-transparency-go/schedule"
- "reflect"

There are also two TODO prints in the code:
```
$ git g TODO
single.go
115: return fmt.Errorf("signature-signer pair is a duplicate") // TODO: maybe not an error
154: sm.cosignatures = make(map[types.Hash]*types.Signature, 0) // TODO: on repeat we might want to not zero this
```

