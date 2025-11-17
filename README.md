![GEN-7 Autonomous Defender Mesh Banner](https://raw.githubusercontent.com/MrServerGuides/DEFENDER-MESH-FIREWALL/main/1763369557974.jpg)

# GEN‑7 Autonomous Defender Mesh

Anti DDOS & Stress Testing

**Author:** ChatGPT+ Pro & Guided By Cybernetics  
**Version:** 7.0  
**Build Date:** 2025‑11‑17  
**License:** MIT / Proprietary (as required)

---

## Overview

GEN‑7 Autonomous Defender Mesh is a **high-performance network defense system** designed for modern high-speed environments. It combines **XDP/eBPF packet capture**, **anomaly detection**, and **dynamic iptables blocking** to provide real-time protection against suspicious traffic.

It continuously monitors traffic, extracts per-IP features, and classifies anomalies using either:

* **GPU-accelerated CuML Isolation Forest** (`mesh_defender.py`)  
* **CPU-based scikit-learn Isolation Forest** (`mesh_defender_cpu.py`)  

Both modes automatically block or unblock IPs based on behavior.

---

## Key Features

* **High-speed packet inspection** using XDP/eBPF.
* **GPU mode:** CuML Isolation Forest on NVIDIA GPUs.
* **CPU mode:** scikit-learn Isolation Forest for GPU-less systems.
* **Dynamic batching** and adaptive classification rates.
* **Real-time tracking** of per-IP PPS (packets per second) and RPS (requests per second).
* **Entropy-based feature extraction** for anomaly detection.
* **Automatic iptables blocking/unblocking** with configurable durations.
* **Multi-threaded classification** using `ThreadPoolExecutor`.
* **Live terminal dashboard** with CPU, RAM, and traffic stats via Rich.
* **Quick-learn mode** for adaptive anomaly thresholding.
* **Production-ready logging** for blocked/unblocked IPs.

---

## Requirements

* **Python 3.11+**
* Libraries:
  * GPU mode: `psutil`, `cupy`, `cuml`, `bcc`, `rich`
  * CPU mode: `psutil`, `scikit-learn`, `bcc`, `rich`
* **Root privileges** required for XDP/eBPF and iptables integration.
* NVIDIA GPU with CUDA support recommended for GPU mode.

---

## Installation

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install required dependencies
sudo apt install python3-pip python3-dev libbcc-dev llvm clang build-essential -y

# Install Python libraries
# GPU mode:
pip3 install psutil cupy cuml bcc rich
# CPU mode:
pip3 install psutil scikit-learn bcc rich
````

---

## Usage

### GPU Mode (Preferred for High Throughput)

```bash
sudo python3 mesh_defender.py
```

### CPU Mode (Fallback for GPU-less Systems)

```bash
sudo python3 mesh_defender_cpu.py
```

### Auto-Launcher (Recommended)

```bash
sudo python3 Check_Support_And_Installer.py
```

* Auto-installs missing dependencies if needed.
* Downloads latest `mesh_defender.py` and `mesh_defender_cpu.py` from GitHub if not present.
* Detects GPU availability and runs the appropriate edition automatically.
* Must run as root to capture packets and enforce iptables rules.
* Dashboard updates live with IP statistics and system load.
* Blocks and unblocks IPs automatically based on anomaly detection.

---

## Configuration

| Parameter        | Description                           | Default |
| ---------------- | ------------------------------------- | ------- |
| `BLOCK_DURATION` | Seconds an IP remains blocked         | 180     |
| `MODEL_UPDATE`   | Seconds between model updates         | 20      |
| `WINDOW`         | Feature history size per IP           | 400     |
| `MAX_WORKERS`    | Threads for async classification      | 6       |
| `MIN_BATCH`      | Minimum batch size for classification | 16      |
| `MAX_BATCH`      | Maximum batch size for classification | 128     |
| `ADAPT_RATE`     | Dynamic batch adjustment factor       | 0.25    |
| `QUICK_LEARN`    | Increase sensitivity to anomalies     | True    |

---

## Operational Notes

* Supports **TCP/UDP IP traffic only**; other protocols are passed through.
* **Dynamic batching** adapts to queue size to optimize GPU or CPU load.
* GPU memory usage scales with batch size; monitor system resources in GPU mode.
* Use terminal dashboard to monitor blocked IPs, PPS, RPS, and system resources.

---

## Logging

* Blocks and unblocks are printed to console in real time.
* Optional: can be extended to `/var/log/mesh_defender.log` for persistent auditing.

---

## Contributing

* Only Python 3.11+ recommended.
* GPU mode requires CuPy and cuML; CPU mode can be used on GPU-less machines.
* Submit PRs with clear notes on changes and performance impact.

---

## Changelog

* **v7.0 (2025‑11‑17)**: GPU & CPU modes, dynamic batching, adaptive classification, Rich live dashboard, auto-launcher script added.
* **v6.x**: Prototype for XDP + GPU traffic monitoring.

---

## Security & Best Practices

* Always run with root privileges.
* Configure `iptables` carefully; ensure non-blocked IPs are trusted.
* Test in staging networks before production deployment.
* Tune batch sizes, ADAPT_RATE, and BLOCK_DURATION based on traffic volume and GPU capacity.

---

## Notes on Multi-Mode Design

* `mesh_defender.py` → GPU mode using **CuML/CuPy**.
* `mesh_defender_cpu.py` → CPU mode using **scikit-learn**.
* `Check_Support_And_Installer.py` → Auto-installs dependencies, downloads latest scripts, detects GPU, and runs the appropriate edition.
* All scripts share **same configuration parameters**, **same XDP/eBPF logic**, and **Rich dashboard**, ensuring consistency between modes.
* Users can switch modes simply by running the appropriate script or using the auto-launcher.
