//! Support shared by the tests of several crates, where a copy in each would
//! drift. Today that is the root-lane guard. The workspace-wide checks are this
//! package's `tests/`.

pub mod root_lane;
