# /proc fixture tree

A minimal, committed `/proc`-shaped tree so `DirSource` is exercised against
real file I/O on every platform, rather than only against the in-memory fake.
A fixture that exercises different code than production proves less than it
appears to, which is why `DirSource` is used here and in production unchanged.

Do not add a process here without a test that reads it.
