# Error handling
- Some error messages are probably too verbose.  We should take a pass over this
and ensure that they are masked appropriately.  A production mode would be nice.
- For some reason our current error messages have one too many new lines.  In
other words, we want `Error: some text\n` and not `Error: some text\n\n`.
