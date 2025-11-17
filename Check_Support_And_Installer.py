#!/usr/bin/env python3
"""
GEN-7 Defender Mesh Auto Launcher
- Installs missing dependencies
- Checks GPU availability
- Downloads latest scripts from GitHub if needed
- Runs GPU or CPU edition automatically
"""

import subprocess
import sys
import importlib.util
import os
import urllib.request

GITHUB_BASE = "https://raw.githubusercontent.com/MrServerGuides/DEFENDER-MESH-FIREWALL/main/"
GPU_SCRIPT_URL = GITHUB_BASE + "mesh_defender.py"
CPU_SCRIPT_URL = GITHUB_BASE + "mesh_defender_cpu.py"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
GPU_SCRIPT_PATH = os.path.join(SCRIPT_DIR, "mesh_defender_gpu.py")
CPU_SCRIPT_PATH = os.path.join(SCRIPT_DIR, "mesh_defender_cpu.py")

REQUIREMENTS = [
    "psutil",
    "numpy",
    "rich",
    "scikit-learn",
    "bcc",
    "cuml;platform_system=='Linux'"
]

def install_package(pkg):
    print(f"[+] Installing {pkg}...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

def check_and_install(pkg):
    if ";" in pkg:
        pkg_name, cond = pkg.split(";")
        if os.name != "posix":
            return
        pkg = pkg_name
    if importlib.util.find_spec(pkg) is None:
        install_package(pkg)

def download_file(url, path):
    try:
        print(f"[+] Downloading {url} -> {path}")
        urllib.request.urlretrieve(url, path)
    except Exception as e:
        print(f"[ERROR] Failed to download {url}: {e}")
        sys.exit(1)

def ensure_scripts():
    if not os.path.isfile(GPU_SCRIPT_PATH):
        download_file(GPU_SCRIPT_URL, GPU_SCRIPT_PATH)
    if not os.path.isfile(CPU_SCRIPT_PATH):
        download_file(CPU_SCRIPT_URL, CPU_SCRIPT_PATH)

def check_gpu():
    try:
        import cupy as cp
        return cp.cuda.runtime.getDeviceCount() > 0
    except Exception:
        return False

def main():
    for pkg in REQUIREMENTS:
        check_and_install(pkg)

    ensure_scripts()

    GPU_AVAILABLE = check_gpu()
    print(f"[+] GPU available: {GPU_AVAILABLE}")

    if GPU_AVAILABLE:
        print("[*] Running GPU edition...")
        subprocess.run([sys.executable, GPU_SCRIPT_PATH])
    else:
        print("[*] Running CPU edition...")
        subprocess.run([sys.executable, CPU_SCRIPT_PATH])

if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("[ERROR] This launcher must be run as root for XDP/eBPF and iptables!")
    main()
