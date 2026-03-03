ANDNA Workspace Fix Patch (stub builds + ffi-cli)

Fixes:
1) Cargo warnings about ignored `default-features` on workspace deps by moving:
     default-features = false
   into [workspace.dependencies] for:
     - andna-core
     - andna-mldsa44

2) Prevents `oqs` / `oqs-sys` from building during stub tests by gating the andna-core
   dev-dependency on oqs behind feature `oqs-backend` using:
     [target.'cfg(feature = "oqs-backend")'.dev-dependencies]

3) Fixes ffi-cli build error:
   - crates/ffi had crate-type = ["staticlib","cdylib"] only, so it did not produce an rlib.
   - added "rlib" so Rust crates can depend on andna-ffi and `use andna_ffi::*;` resolves.

Apply:
- Unzip into repo root (C:\andna-core) and overwrite:
    Cargo.toml
    crates/core/Cargo.toml
    crates/ffi/Cargo.toml

Then run:
  cargo clean
  cargo test --all --no-default-features --features stub

Expected:
- no `default-features ignored` warnings
- no oqs/oqs-sys build during stub tests
- ffi-cli compiles
