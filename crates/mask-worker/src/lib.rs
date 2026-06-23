//! Library surface of the `mask` VGI worker.
//!
//! The binary (`main.rs`) is the actual worker; this `lib` target exposes the
//! pure masking engine so integration tests under `tests/` can exercise it
//! directly, without Arrow or RPC. See [`mask`] for the engine.

pub mod mask;
