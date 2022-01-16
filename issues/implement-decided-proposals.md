**Title:** Implement decided proposals </br>
**Date:** 2022-01-16 </br>

# Summary
Implement decided proposals according to the latest Sigsum v0 API.

# Description
Several proposals were decided to feature freeze the Sigsum v0 API.  These
proposals were documented in:

	sigsum/archive/2022-01-04-proposal*
	sigsum/doc/2021-11*

There is a draft on bringing the above into main documentation in

	rgdd/proposals 

Current status on implementing the above:

* [x] open-ended shard interval
* [ ] ssh signing format
	* implement in sigsum-lib-go by updating `ToBinary()`
	* then pick up the new sigsum-lib-go version in sigsum-log-go
* [ ] remove arbitrary bytes
* [ ] get-\* endpoints
* [ ] domain hint
* [ ] add-leaf
* [ ] tree-head endpoints
	* rgdd is assigned, started on something similar in `rgdd/state`
