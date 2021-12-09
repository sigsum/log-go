**Title:** Add read-only mode </br>
**Date:** 2021-12-09 </br>

# Summary
A read-only mode is needed to facilitate maintenance and shutdowns of production
logs.  For example, after an operator has decided to cease their operations the
log in question should be kept around for some time to allow final monitoring.

# Description
This issue requires design considerations.  For inspiration, you may refer to 
	[CTFE](https://github.com/google/certificate-transparency-go/tree/master/trillian/ctfe).

At minimum it should be possible to (i) disable all write endpoints, and (ii)
serve a cosigned tree head for all add-leaf requests that were already merged.

It would be good to consider if we need a mirror-mode before getting started.
