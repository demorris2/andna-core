# AN-DNA FIPS 140-3 Operational Environments

**Document:** `/fips/operational_environments.md`
**Status:** Draft — Pre-CST Lab Submission
**Version:** 1.0.0
**Date:** 2026-03-10
**Prepared by:** Darrell Morris Jr. — ArcNeura
**Reference:** FIPS 140-3, NIST SP 800-140, CMVP Implementation Guidance (IG)

---

## 1. Overview

This document defines the Tested Operational Environment (OE) and Vendor Affirmed
Environments for the AN-DNA Core Verification Library (`libandna_ffi.so` / `libandna_ffi.a`).

Per FIPS 140-3 requirements for software cryptographic modules, each operational environment
is defined by its operating system, platform, processor, and hypervisor status. The CMVP
certificate will list only the Tested OE. Vendor Affirmed Environments are documented here
per CMVP Implementation Guidance and allow compliant deployment on compatible platforms
without additional CST lab testing.

---

## 2. Tested Operational Environment

### OE-1 (Tested — CST Lab)

This is the environment under which the module will be tested by the accredited CST
laboratory. All CAVP algorithm testing and FIPS 140-3 functional testing will be performed
in this environment.

| Field | Value |
|---|---|
| **OE Identifier** | OE-1 |
| **Operating System** | Ubuntu 22.04 LTS (Jammy Jellyfish) |
| **OS Version** | 22.04.x (kernel 5.15.x or later) |
| **Platform** | General Purpose Computer (GPC) |
| **Processor** | Intel Xeon (x86\_64 architecture) |
| **Hypervisor** | None — Bare-metal / Standard Cloud Compute |
| **Modifiable Operational Environment** | Yes |
| **Multi-chip Embodiment** | No — single-chip software module |
| **Runtime** | Standard Linux userspace — no special runtime required |

**Rationale:** OE-1 matches the GitHub Actions Host B environment used for Gate 1
cross-platform verification. Ubuntu 22.04 LTS on x86\_64 with no hypervisor is the
environment in which the Golden Hash
`231778903c6c2c345d3eaba423800bc7ec3edb42750518034f083cba40a2ecef` was independently
produced and verified.

---

## 3. Vendor Affirmed Environments

Per CMVP Implementation Guidance, the vendor affirms that the AN-DNA Core Verification
Library functions correctly and maintains its FIPS-approved security status on the following
environments. No source code modifications are made for these environments. No additional
CST lab testing is required for affirmed environments.

> **Note:** Only OE-1 appears on the CMVP certificate. Vendor Affirmed Environments are
> documented for procurement reference, enabling deploying organizations to confirm compliant
> use on their platforms.

### OE-2 (Vendor Affirmed)

| Field | Value |
|---|---|
| **OE Identifier** | OE-2 |
| **Operating System** | Windows 11 with WSL2 (Windows Subsystem for Linux 2) |
| **Architecture** | x86\_64 |
| **Hypervisor** | WSL2 lightweight VM (Microsoft Hyper-V based) |
| **Affirmed Basis** | Gate 1 Host A ran under Windows/WSL2 and produced a byte-identical `libandna_ffi.so` matching the Golden Hash. WSL2 is a Linux userspace environment; the artifact produced is a Linux `.so`, not a native Windows DLL. Native Windows (MSVC/MinGW) DLL compilation is a separate build target outside this validation lane. |

> **Note:** A native Windows `andna_ffi.dll` (compiled with MSVC or MinGW64 targeting `x86_64-pc-windows-gnu`) is used in the development environment (Host A local) but is a distinct artifact from `libandna_ffi.so` and is not within the Approved Mode validation lane. The validated artifact is `libandna_ffi.so` produced within WSL2 or a Linux environment.

### OE-3 (Vendor Affirmed)

| Field | Value |
|---|---|
| **OE Identifier** | OE-3 |
| **Operating System** | Red Hat Enterprise Linux (RHEL) 9 |
| **Architecture** | x86\_64 |
| **Hypervisor** | None |
| **Affirmed Basis** | Binary-compatible with OE-1 (same glibc ABI baseline). No source modifications required. |

### OE-4 (Vendor Affirmed)

| Field | Value |
|---|---|
| **OE Identifier** | OE-4 |
| **Operating System** | Ubuntu 24.04 LTS (Noble Numbat) |
| **Architecture** | x86\_64 |
| **Hypervisor** | None |
| **Affirmed Basis** | Forward-compatible with OE-1. Same glibc ABI. No source modifications required. |

---

## 4. Environments Explicitly Out of Scope

The following environments are not tested and not vendor-affirmed for the current validation.
Deployment in these environments does not constitute FIPS-compliant use of this module.

| Environment | Reason |
|---|---|
| ARM / AArch64 | Not tested. Architecture-specific compiler behavior may affect determinism. Requires separate Gate 1 verification pass. |
| RISC-V | Not tested. |
| 32-bit x86 | Not tested. Module targets 64-bit only. |
| macOS (any version) | Not tested. Dynamic linker and C ABI differences from Linux. |
| Containerized environments (Docker, Kubernetes) | The module may function correctly but the container runtime layer is not a defined OE for this validation. |
| Cloud confidential compute (AMD SEV, Intel TDX) | Hypervisor presence changes the OE definition. Not tested. |

---

## 5. Hypervisor Note

For OE-1 through OE-4, no hypervisor is present in the operational environment. If a deploying
organization runs the module inside a virtual machine (e.g., VMware, Hyper-V, KVM), that
constitutes a different operational environment than defined here. Per FIPS 140-3 guidance,
hypervisor presence must be listed as part of the OE definition. Such deployments are outside
the scope of this validation.

---

## 6. Modifiable vs. Non-Modifiable Environment

All defined OEs (OE-1 through OE-4) are classified as **modifiable** operational environments
per FIPS 140-3 terminology — the underlying OS and hardware can be modified by parties
other than the module vendor. This is standard for software modules on general-purpose
computing platforms and is fully supported at FIPS 140-3 Level 1.

---

## 7. Non-Claims

- This document does not claim FIPS 140-3 validation for any listed environment.
- Vendor affirmation is a vendor statement, not a CMVP-tested claim.
- Only OE-1 will appear on the issued CMVP certificate.

---

## 8. Revision History

| Version | Date | Change |
|---|---|---|
| 1.0.0 | 2026-03-10 | Initial draft. OE-1 anchored to Gate 1 Host B verification. |
| 1.1.0 | 2026-03-10 | Corrected OE-2: Gate 1 Host A ran under WSL2 (Linux environment), produces `libandna_ffi.so` not a native Windows DLL. Added note distinguishing WSL2 build lane from native Windows MSVC/MinGW build target. |
