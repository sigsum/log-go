**Title:** Fix error-prone timestamp configuration</br>
**Date:** 2021-12-18 </br>

# Summary
Stop relying on Trillian to update tree head timestamps.

# Description
A sigsum log is expected to produce a new to-sign tree head every five minutes.
If no new entries were added, only the timestamp is updated to ensure freshness.

The current sigsum-log-go implementation assumes that Trillian ensures that a
new tree head is produced every five minutes.  It can be configured as follows:
```
$ createtree --help
Usage of ./createtree:
[...]
  -max_root_duration duration
        Interval after which a new signed root is produced despite no submissions; zero means never (default 1h0m0s)
[...]
```

It would be less error-prone to configure this from sigsum-log-go instead, as
part of the `StateManager` interface based on a constant (i.e., 5 minutes).
