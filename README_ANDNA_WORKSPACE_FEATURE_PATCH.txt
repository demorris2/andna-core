ANDNA workspace feature-gating patch (stub build fix)

Symptom:
- `cargo test --all --no-default-features --features stub` still builds `oqs-sys` (liboqs + OpenSSL),
  and you see warnings like:
    "`default-features` is ignored ... since `default-features` was not specified for workspace.dependencies..."

Root cause:
- When a dependency is declared with `workspace = true`, Cargo takes feature defaults from
  `[workspace.dependencies]`. If you want default features OFF for internal crates
  (so stub builds don't pull liboqs), you must set `default-features = false` there.

Changes:
1) Root `Cargo.toml`:
   - Set `default-features = false` for:
       andna-mldsa44
       andna-core
2) Remove the now-ignored `default-features = false` overrides from:
   - crates/core/Cargo.toml
   - crates/ffi/Cargo.toml

After applying:
- The warnings disappear.
- Stub builds no longer compile `oqs` / `oqs-sys`.
- Real builds still work via `--features oqs-backend`.

Commands to verify:
  cargo clean
  cargo test --all --no-default-features --features stub
  cargo tree -e features | rg "oqs|oqs-sys|andna-mldsa44"
