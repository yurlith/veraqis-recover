//! Architecture-fitness test (Phase 0.5 trust boundary).
//!
//! The analysis **Core** (`phx_analyze_engine`) must never depend on
//! `phx_sandbox`. Core consumes already-bounded, traversal-safe data (a
//! `ContainerTree`) only; every operation that opens files for write,
//! decompresses attacker-controlled bytes, recurses into containers, or spawns
//! processes lives behind the trust boundary in `phx_sandbox`.
//!
//! If this test fails, a dependency edge from Core into the sandbox crate was
//! introduced — remove it and pass the bounded data across the boundary
//! instead.

#[test]
fn core_does_not_depend_on_sandbox() {
    let manifest = include_str!("../Cargo.toml");
    assert!(
        !manifest.contains("phx_sandbox"),
        "phx_analyze_engine (Core) must not depend on phx_sandbox: the trust \
         boundary requires Core to consume a bounded ContainerTree only, never \
         the sandbox internals"
    );
}
