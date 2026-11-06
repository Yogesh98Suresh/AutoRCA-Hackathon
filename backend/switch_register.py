"""Explicit one-time operator command for registering AutoRCA with Switch.

Run with: python -m backend.switch_register
The command prints the returned agent API key once. Capture it securely.
"""

import os
import platform
import re
import ctypes
from ctypes import wintypes

from backend.switch_client import SwitchHTTPClient
from backend.switch_config import SwitchSettings, validate_agent_base_url


def store_windows_credential(target: str, username: str, secret: str) -> None:
    """Store the agent key in the current Windows user's Credential Manager."""
    if platform.system() != "Windows":
        raise RuntimeError("Secure registration storage is implemented only for Windows Credential Manager.")

    class Credential(ctypes.Structure):
        _fields_ = [
            ("Flags", wintypes.DWORD), ("Type", wintypes.DWORD),
            ("TargetName", wintypes.LPWSTR), ("Comment", wintypes.LPWSTR),
            ("LastWritten", wintypes.FILETIME), ("CredentialBlobSize", wintypes.DWORD),
            ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)), ("Persist", wintypes.DWORD),
            ("AttributeCount", wintypes.DWORD), ("Attributes", ctypes.c_void_p),
            ("TargetAlias", wintypes.LPWSTR), ("UserName", wintypes.LPWSTR),
        ]

    blob = secret.encode("utf-8")
    buffer = ctypes.create_string_buffer(blob)
    entry = Credential(0, 1, target, None, wintypes.FILETIME(), len(blob),
                       ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)), 2, 0, None, None, username)
    advapi = ctypes.WinDLL("Advapi32.dll", use_last_error=True)
    writer = advapi.CredWriteW
    writer.argtypes = [ctypes.POINTER(Credential), wintypes.DWORD]
    writer.restype = wintypes.BOOL
    if not writer(ctypes.byref(entry), 0):
        raise RuntimeError(f"Windows Credential Manager write failed ({ctypes.get_last_error()}).")


def main() -> int:
    base_url = os.getenv("AUTORCA_SWITCH_AGENT_BASE_URL", "").strip().rstrip("/")
    registration_key = os.getenv("AUTORCA_SWITCH_REGISTRATION_API_KEY", "")
    name = os.getenv("AUTORCA_SWITCH_AGENT_NAME", "autorca").strip()
    if not base_url or not registration_key:
        raise SystemExit("Set AUTORCA_SWITCH_AGENT_BASE_URL and AUTORCA_SWITCH_REGISTRATION_API_KEY for this one-time command.")
    if platform.system() != "Windows":
        raise SystemExit("Registration is disabled here because this command cannot store the returned key in Windows Credential Manager.")
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", name):
        raise SystemExit("AUTORCA_SWITCH_AGENT_NAME must match ^[a-z0-9][a-z0-9._-]*$.")
    try:
        base_url = validate_agent_base_url(base_url)
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from None
    settings = SwitchSettings(agent_base_url=base_url)
    result = SwitchHTTPClient(settings).register_agent(
        registration_key,
        {"connection_model": "always_on", "message_exchange": True,
         "pre_invocation_mediation": [], "post_invocation_mediation": [], "event_reporting": []},
        name=name,
        description="Analyzes service logs and coordinates human-reviewed incident investigations.",
    )
    target = f"AutoRCA/Switch/{result['id']}"
    store_windows_credential(target, result["id"], result["api_key"])
    print(f"Registered Switch agent id: {result['id']}")
    print(f"Agent API key stored in the current user's Windows Credential Manager as: {target}")
    print("The key was not printed. Retrieve it through your approved secret handling process before setting the server environment.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
