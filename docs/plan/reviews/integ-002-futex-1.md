# integ-002-futex Review 1

## Findings

No blocking findings for this slice.

Reviewed scope:

- `crates/mcr-runtime/src/lib.rs` process-private futex `WAIT`/`WAKE` behavior.
- Timeout pointer parsing and Linux errno mapping for invalid `timespec`, timeout, and host sync errors.
- Regression coverage that matching-value null-timeout waits no longer return fake success or create fake waiter counts.

Scope note:

- This slice intentionally does not complete real indefinite guest blocking. A matching-value null-timeout wait now returns `EAGAIN` instead of fake success until the runtime has a real task blocking/resume loop.
- Full integ-002 remains blocked on guest execution loop integration and real Alpine shell smoke.

Verification:

- `cargo fmt --check`: pass.
- `cargo test -p mcr-runtime futex --lib -- --nocapture`: pass.
- `cargo test -p mcr-runtime --lib`: pass.
- `cargo clippy -p mcr-runtime --all-targets -- -D warnings`: pass.
- `cargo test -p mcr-win sync --lib`: pass.

## Conclusion

pass
