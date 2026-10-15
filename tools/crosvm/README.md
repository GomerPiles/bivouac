# Experimental Windows Crosvm runtime

`public_ipv4.rs` is the Bivouac packet admission module.
`windows-runtime.patch` applies to Crosvm
`b2c03d01cdee82e72707ec34c470805d5998ab5f` and includes loopback-only SSH
management forwarding, the pre-Slirp packet hook, IPv6/host-loopback disabling,
and the previously tested Windows net/input/QCOW portability fixes. Copy the
module as `third_party/libslirp-rs/src/bivouac_public.rs` after applying the
patch. These source changes preserve Crosvm's upstream licensing; the new
module is MIT licensed. No third-party binary is redistributed here.

The tested runtime uses gfxstream
`07ee40efb0e7037a9a9b7fe59071e7c4997e7cbe` (ABI 0.1.2), rutabaga 0.1.80,
Vulkano 0.33 and libslirp 4.7.0. The guest uses matching Mesa 26.0.8 gfxstream.
Keep the native DLLs beside the executable and preserve their licence notices.
Operators supply and verify this bundle; Bivouac does not download it or
silently replace a production runtime. Pin the tested executable digest in
configuration, and keep its complete DLL bundle immutable.

The portable build used Rust 1.88.0, LLVM-MinGW 20261006 UCRT/Clang 23.1.3,
and `x86_64-pc-windows-gnullvm`. A GNU-host Rust toolchain can cross-build that
target. The [official target documentation](https://doc.rust-lang.org/rustc/platform-support/windows-gnullvm.html)
describes the UCRT/LLVM combination. The GNU/MSVCRT target linked against this
UCRT library bundle crashed before argument parsing and was not used.

```text
cargo build --target x86_64-pc-windows-gnullvm --release --locked --no-default-features --features gpu,gfxstream,whpx,balloon,vulkano,net,slirp,qcow --jobs 4
```

Set `GFXSTREAM_PATH` to the verified local gfxstream import-library directory;
set the target linker, `CC` and `CXX` to the portable LLVM tools. The Windows
build also needs real import libraries, not stubs: LLVM's SDK libraries cover
runtimeobject/shcore, and the pinned WinAPI dependency supplies sporder.
GNU-host build scripts need libgcc/libgcc_eh from GCC 16.2.0-5. The tested
[MSYS2 package](https://packages.msys2.org/packages/mingw-w64-x86_64-gcc)
archive has SHA-256
`97f6eb042afbb1d27237a4479ea444acb3d594789bba5e0182360d2c4b983b88`.
Stage these only in a private build directory. This records the tested manual
build prerequisites; a fully automated clean-room runtime build is still pending.

The nine standalone policy tests require no VM or administrator privilege;
CI runs them on Linux:

```text
rustc --test --edition 2021 public_ipv4.rs -o policy-tests.exe
policy-tests.exe
```

The Go provider always supplies `BIVOUAC_SLIRP_POLICY=public-ipv4-v1` and the
canonical `BIVOUAC_SLIRP_HOST_PREFIXES` inventory. A missing, malformed or
unknown value panics before Slirp initialization, so no guest traffic reaches
host sockets. Only `BIVOUAC_SLIRP_POLICY=unfiltered-positive-control` runs the
patched binary unfiltered, for positive-control comparisons; the provider
strips any inherited value and never supplies it. Native loopback SSH
management requires `CROSVM_SLIRP_SSH_PORT`; no other host port forwarding is
added. Changing `public_ipv4.rs` requires rebuilding the runtime and pinning
its new digest.

Windows process containment follows Microsoft's
[atomic job assignment API](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute).
Do not regress to creating a live child and assigning its job afterward.
Networking and hostile-guest readiness limits are in
[`docs/crosvm.md`](../../docs/crosvm.md).
