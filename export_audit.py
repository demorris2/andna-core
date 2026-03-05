import ctypes, os, sys

lib_path = os.environ.get("ANDNA_LIB_PATH")
if not lib_path:
    print("ANDNA_LIB_PATH not set", file=sys.stderr)
    raise SystemExit(2)

lib = ctypes.CDLL(lib_path)
lib.andna_audit_export_jsonl.argtypes = [ctypes.c_char_p]
lib.andna_audit_export_jsonl.restype = ctypes.c_int

rc = lib.andna_audit_export_jsonl(b"andna_audit.jsonl")
print("rc=", rc)
