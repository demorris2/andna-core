import os
import sys
import ctypes
from pathlib import Path

# Adjust only if your paths differ
MAIN_DLL = Path(r"C:\andna-core\target\release\andna_ffi.dll")
SEARCH_DIRS = [
    MAIN_DLL.parent,
    Path(r"C:\msys64\mingw64\bin"),
]

# Likely dependencies for a MinGW-built Rust DLL using liboqs/OpenSSL
CANDIDATES = [
    "liboqs.dll",
    "libssl-3-x64.dll",
    "libcrypto-3-x64.dll",
    "libgcc_s_seh-1.dll",
    "libstdc++-6.dll",
    "libwinpthread-1.dll",
]

def print_header(title: str) -> None:
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)

def try_load(label: str, path: str):
    try:
        dll = ctypes.CDLL(path)
        print(f"[OK]   {label}: loaded")
        return True, dll
    except OSError as e:
        print(f"[FAIL] {label}: {e}")
        return False, None

def main():
    print_header("AN-DNA DLL Load Probe")

    print(f"Python: {sys.executable}")
    print(f"Version: {sys.version.split()[0]}")
    print(f"MAIN_DLL: {MAIN_DLL}")
    print(f"Exists: {MAIN_DLL.exists()}")

    if not MAIN_DLL.exists():
        print("\nMain DLL does not exist. Stop here and rebuild.")
        sys.exit(1)

    # Keep handles alive for the process lifetime
    dll_dirs = []

    print_header("Register DLL search directories")
    for d in SEARCH_DIRS:
        print(f"Dir: {d} (exists={d.exists()})")
        if d.exists():
            try:
                handle = os.add_dll_directory(str(d))
                dll_dirs.append(handle)
                print(f"  [OK] added")
            except (AttributeError, FileNotFoundError, OSError) as e:
                print(f"  [WARN] could not add: {e}")

    print_header("Probe likely dependency DLLs individually")
    loaded = {}
    for name in CANDIDATES:
        found_path = None
        for d in SEARCH_DIRS:
            candidate = d / name
            if candidate.exists():
                found_path = candidate
                break

        if found_path is None:
            print(f"[MISS] {name}: not found in search dirs")
            loaded[name] = False
            continue

        ok, _ = try_load(name, str(found_path))
        loaded[name] = ok

    print_header("Probe main AN-DNA DLL")
    ok, lib = try_load("andna_ffi.dll", str(MAIN_DLL))
    if not ok:
        print("\nMain DLL still failed to load.")
        print("If all visible dependencies loaded above, then a transitive dependency")
        print("is still missing. Use dumpbin /dependents or Dependencies.exe for exact tree.")
        sys.exit(2)

    print_header("Probe exported symbols")
    for sym in [
        "andna_verify_frame_v2",
        "andna_gen_test_frame",
        "andna_audit_export_jsonl",
    ]:
        has = hasattr(lib, sym)
        print(f"{sym}: {'FOUND' if has else 'MISSING'}")

    print_header("Summary")
    failed = [name for name, ok in loaded.items() if not ok]
    if failed:
        print("Dependency probe failures:")
        for name in failed:
            print(f" - {name}")
    else:
        print("All probed dependency DLLs loaded.")
    print("Main DLL loaded successfully.")

if __name__ == "__main__":
    main()