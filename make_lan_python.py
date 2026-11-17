#!/usr/bin/env python3
"""make_lan_python.py - give Python a stable, Chrome-like app identity on macOS
and request Local Network access for it once.

Why the permission keeps resetting: macOS tracks Local Network approval by the
app's code signature + the Mach-O UUID of its executable. Homebrew/pyenv/uv
Python binaries change on every update (and are ad hoc signed), so each update
looks like a brand-new app. Chrome keeps its approval because it's a signed
app bundle with a fixed identity.

This script does the same for Python:
  1. builds ~/Applications/PythonLAN.app - a tiny launcher binary that embeds
     YOUR Python (same stdlib, same site-packages); the launcher binary is
     built once and never changes, so its identity never changes
  2. adds NSLocalNetworkUsageDescription to its Info.plist (like real apps)
  3. signs it (ad hoc by default, or with --sign "Your Cert Name")
  4. runs it once doing local-network traffic, which makes macOS show
     "Python LAN would like to find and connect to devices on your local
     network" -> click Allow. The approval then survives Python updates.

Usage (run with the Python you want to use, e.g. your venv's python):
  python3 make_lan_python.py              # build (if needed) + request access
  python3 make_lan_python.py request      # just trigger the prompt again
  python3 make_lan_python.py build --force  # rebuild (new identity -> re-approve)

Afterwards run scripts with:
  ~/Applications/PythonLAN.app/Contents/MacOS/python3 your_script.py
and point LaunchAgents / IDE interpreters at that path.

Requires: macOS, Xcode Command Line Tools (`xcode-select --install`).
"""
import argparse
import os
import plistlib
import shutil
import site
import subprocess
import sys
import sysconfig
import tempfile
import time

APP = os.path.expanduser("~/Applications/PythonLAN.app")
EXE = os.path.join(APP, "Contents", "MacOS", "python3")
BUNDLE_ID = "local.pythonlan"
NAME = "Python LAN"
LOG = os.path.expanduser("~/Library/Logs/PythonLAN-request.log")

LAUNCHER_C = r"""
#include <Python.h>
#include <stdio.h>
#include <stdlib.h>

static const char *LAN_HOME = %(home)s;
static const char *LAN_EXTRA = %(extra)s;

int main(int argc, char **argv) {
    PyStatus st;
    PyConfig c;
    PyConfig_InitPythonConfig(&c);

    st = PyConfig_SetBytesString(&c, &c.home, LAN_HOME);
    if (PyStatus_Exception(st)) goto fail;

    if (LAN_EXTRA[0]) {
        static char buf[16384];
        const char *env = getenv("PYTHONPATH");
        if (env && env[0]) snprintf(buf, sizeof buf, "%%s:%%s", env, LAN_EXTRA);
        else snprintf(buf, sizeof buf, "%%s", LAN_EXTRA);
        st = PyConfig_SetBytesString(&c, &c.pythonpath_env, buf);
        if (PyStatus_Exception(st)) goto fail;
    }

    st = PyConfig_SetBytesArgv(&c, argc, argv);
    if (PyStatus_Exception(st)) goto fail;
    st = Py_InitializeFromConfig(&c);
    if (PyStatus_Exception(st)) goto fail;
    PyConfig_Clear(&c);
    return Py_RunMain();

fail:
    PyConfig_Clear(&c);
    if (PyStatus_IsExit(st)) return st.exitcode;
    Py_ExitStatusException(st);
}
"""

# Code run inside the app to make macOS show the Local Network prompt.
REQUEST_CODE = r"""
import socket, subprocess, sys, time
print("running as:", sys.executable, flush=True)
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    s.sendto(b"\x00" * 12, ("224.0.0.251", 5353))   # mDNS, like Chrome's discovery
    print("multicast: sent", flush=True)
except OSError as e:
    print("multicast:", e, flush=True)
gw = None
try:
    out = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True).stdout
    gw = next((l.split()[-1] for l in out.splitlines() if "gateway:" in l), None)
except Exception:
    pass
for attempt in range(20):           # keep trying while the user answers the prompt
    if not gw:
        break
    try:
        socket.create_connection((gw, 80), timeout=2).close()
        print(f"gateway {gw}: reachable -> access GRANTED", flush=True)
        break
    except ConnectionRefusedError:
        print(f"gateway {gw}: reachable (port closed) -> access GRANTED", flush=True)
        break
    except OSError as e:
        print(f"gateway {gw}: {e} (waiting for you to click Allow...)", flush=True)
        time.sleep(3)
"""


def c_str(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def cfg(name: str) -> str:
    return sysconfig.get_config_var(name) or ""


def list_sdks() -> list:
    """Installed macOS SDKs, newest first, skipping the generic MacOSX.sdk symlink."""
    import glob
    import re
    found = set()
    for pattern in ("/Library/Developer/CommandLineTools/SDKs/MacOSX*.sdk",
                    "/Applications/Xcode*.app/Contents/Developer/Platforms/"
                    "MacOSX.platform/Developer/SDKs/MacOSX*.sdk"):
        for p in glob.glob(pattern):
            if os.path.basename(p) != "MacOSX.sdk":
                found.add(os.path.realpath(p))

    def ver(p):
        m = re.search(r"MacOSX(\d+(?:\.\d+)*)\.sdk", p)
        return tuple(int(x) for x in m.group(1).split(".")) if m else (0,)
    return sorted(found, key=ver, reverse=True)


def build(force: bool, sign: str) -> None:
    if sys.platform != "darwin":
        sys.exit("This only makes sense on macOS.")
    if os.path.exists(EXE) and not force:
        print(f"Already built: {EXE}  (use 'build --force' to rebuild; you'll need to re-approve)")
        return
    if not shutil.which("cc"):
        sys.exit("No C compiler. Run: xcode-select --install")

    home = sys.base_prefix
    extra = ""
    if sys.prefix != sys.base_prefix:           # running from a venv: include its packages
        extra = ":".join(p for p in site.getsitepackages() if p.startswith(sys.prefix))

    libdir = cfg("LIBDIR")
    ldver = cfg("LDVERSION") or cfg("VERSION")
    include = cfg("INCLUDEPY")

    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "launcher.c")
        with open(src, "w") as f:
            f.write(LAUNCHER_C % {"home": c_str(home), "extra": c_str(extra)})
        out = os.path.join(tmp, "python3")
        cc = os.environ.get("CC", "cc").split()
        base = cc + ["-O2", src, "-o", out, f"-I{include}", f"-L{libdir}",
                     f"-lpython{ldver}", f"-Wl,-rpath,{libdir}"]
        base += (cfg("LIBS") + " " + cfg("SYSLIBS")).split()

        # Try the default SDK first, then every other installed SDK (newest first).
        # Fixes "tapi error: malformed file / unknown architecture" when the
        # Command Line Tools' linker is older than its newest SDK.
        attempts = [None] + list_sdks()
        print("Compiling launcher...")
        for sdk in attempts:
            cmd = base + (["-isysroot", sdk] if sdk else [])
            r = subprocess.run(cmd, capture_output=True, text=True)
            if r.returncode == 0:
                if sdk:
                    print(f"  built with SDK {sdk}")
                break
            print(f"  failed with {'default SDK' if not sdk else sdk}: "
                  f"{(r.stderr.strip().splitlines() or ['?'])[0]}")
        else:
            sys.exit(
                "\nCould not link with any installed SDK. Your Command Line Tools are\n"
                "probably half-updated. Reinstall them, then re-run this script:\n"
                "  sudo rm -rf /Library/Developer/CommandLineTools\n"
                "  xcode-select --install\n"
                "(or install pending updates: softwareupdate --list / --install --all)")

        if os.path.exists(APP):
            shutil.rmtree(APP)
        os.makedirs(os.path.dirname(EXE))
        shutil.copy2(out, EXE)

    info = {
        "CFBundleIdentifier": BUNDLE_ID,
        "CFBundleName": NAME,
        "CFBundleDisplayName": NAME,
        "CFBundleExecutable": "python3",
        "CFBundlePackageType": "APPL",
        "CFBundleVersion": "1",
        "CFBundleShortVersionString": "1.0",
        "LSUIElement": True,
        "NSLocalNetworkUsageDescription":
            "Python scripts run with this interpreter connect to devices on your local network.",
        "NSBonjourServices": ["_http._tcp", "_https._tcp", "_ssh._tcp"],
    }
    with open(os.path.join(APP, "Contents", "Info.plist"), "wb") as f:
        plistlib.dump(info, f)

    print(f"Signing ({'ad hoc' if sign == '-' else sign})...")
    subprocess.run(["codesign", "--force", "--deep", "--sign", sign,
                    "--identifier", BUNDLE_ID, APP], check=True)
    # Sanity check: the embedded interpreter starts and sees the right stdlib/packages.
    subprocess.run([EXE, "-c", "import sys,ssl;print('launcher OK:', sys.version.split()[0], sys.prefix)"],
                   check=True)
    print(f"Built {APP}")


def request() -> None:
    if not os.path.exists(EXE):
        sys.exit("Not built yet. Run without arguments first.")
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    open(LOG, "w").close()
    print("Launching Python LAN - click **Allow** when macOS asks about the local network...")
    # Launch through LaunchServices so the app itself (not Terminal) is the
    # responsible process - that's what makes macOS ask on its behalf.
    subprocess.run(["open", "-W", "-n", "--stdout", LOG, "--stderr", LOG,
                    "-a", APP, "--args", "-I", "-c", REQUEST_CODE])
    time.sleep(0.5)
    print(open(LOG).read().strip())
    print(f"\nUse it as:  {EXE} your_script.py")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("action", nargs="?", default="all", choices=["all", "build", "request"])
    ap.add_argument("--force", action="store_true", help="rebuild even if it exists")
    ap.add_argument("--sign", default="-",
                    help='codesign identity (default ad hoc "-"); a Keychain cert name is more robust')
    a = ap.parse_args()
    if a.action in ("all", "build"):
        build(a.force, a.sign)
    if a.action in ("all", "request"):
        request()


if __name__ == "__main__":
    main()

