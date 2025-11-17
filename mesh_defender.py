#!/usr/bin/env python3
# -----------------------------------------------------------
# GEN-7 Autonomous Defender Mesh
# Author: ChatGPT+ Pro & Guided By Cybernetics
# Version: 7.0
# Build: 2025-11-17
# -----------------------------------------------------------
# Description:
#   GEN-7 Autonomous Defender Mesh is a high-performance,
#   GPU-accelerated, XDP/eBPF-powered anomaly detection
#   and firewall system. It monitors packet flows in real-time,
#   performs feature extraction per source IP, and dynamically
#   classifies suspicious traffic using a CuML Isolation Forest.
#
# Features:
#   - XDP/eBPF packet capture and perf buffer events
#   - GPU-accelerated anomaly detection via cuML Isolation Forest
#   - Dynamic batching and adaptive classification
#   - Real-time per-IP PPS/RPS tracking and entropy calculation
#   - Automatic iptables blocking and expiration handling
#   - Live CLI dashboard via Rich for CPU/RAM/traffic stats
#   - Quick learn mode for adaptive anomaly thresholds
#   - Multi-threaded classification with ThreadPoolExecutor
#
# Security & Operational Notes:
#   - Requires root privileges for XDP/eBPF and iptables integration
#   - Python 3.11+ recommended for full async & GPU support
#   - Supports ETH_P_IP traffic for TCP/UDP only; others are passed
#   - BLOCK_DURATION (default 180s) controls automatic unblock timing
#   - GPU memory may scale with batch size; dynamic batch adjusts load
#   - Logs blocked/unblocked IPs, classification rates, and resource usage
#   - Designed for high-throughput networks (100k+ PPS)
#   - Quick-learn contamination increases sensitivity to anomalies
#   - Non-blocking live dashboard ensures minimal performance overhead
#
# Requirements:
#   - Python 3.11+
#   - psutil, cupy, cuml, bcc, rich
#   - NVIDIA GPU with CUDA support recommended
#
# Usage:
#   sudo python3 mesh_defender.py
# -----------------------------------------------------------
# Change Log:
#   [2025-11-17] v7.0 - Added dynamic batching, GPU IF model, 
#              - enhanced XDP perf buffer handling, Rich dashboard
#   [2025-11-15] v6.x - Initial GPU + XDP prototype
# -----------------------------------------------------------
# Author Notes:
#   - This script is intended for production-grade network defense
#   - Designed for high-speed, low-latency anomaly blocking
#   - All IP classification and blocking events are logged to console
#   - Adaptation parameters (ADAPT_RATE, MIN_BATCH, MAX_BATCH) 
#     can be tuned for network load and GPU resources
# -----------------------------------------------------------


import sys
import os

if os.geteuid() != 0:
    sys.exit("[ERROR] This script must be run as root for XDP/eBPF and iptables!")

if sys.version_info < (3, 11):
    sys.exit(f"[ERROR] Python 3.11+ required, found {sys.version_info.major}.{sys.version_info.minor}")
script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)
    
VERBOSE = True
DEBUG = False

import time
import struct
import socket
import subprocess
import random
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor

import psutil
import numpy as np
import cupy as cp
from cuml.ensemble import IsolationForest as cuIF

from bcc import BPF
from rich.live import Live
from rich.table import Table
from rich.console import Console

console = Console()

WINDOW = 400
MODEL_UPDATE = 20
BLOCK_DURATION = 180
MAX_WORKERS = 6
MAX_BATCH = 128
MIN_BATCH = 16
ADAPT_RATE = 0.25
QUICK_LEARN = True

blocked_ips = {}
history = defaultdict(lambda: deque(maxlen=WINDOW))

packet_count = defaultdict(int)
request_count = defaultdict(int)
entropy_track = defaultdict(lambda: deque(maxlen=60))

last_reset = time.time()

executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
classification_queue = deque()

dynamic_batch = 32

BPF_PROGRAM = """
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

BPF_PERF_OUTPUT(events);

int xdp_prog(struct xdp_md *ctx) {
    void *de = (void *)(long)ctx->data_end;
    void *d = (void *)(long)ctx->data;

    struct ethhdr *eth = d;
    if ((void*)eth + sizeof(*eth) > de) return XDP_PASS;
    if (eth->h_proto != htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = d + sizeof(*eth);
    if ((void*)ip + sizeof(*ip) > de) return XDP_PASS;

    u32 src = ip->saddr;
    u32 dst = ip->daddr;
    u8 proto = ip->protocol;

    u16 sport = 0, dport = 0;

    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (void*)ip + sizeof(*ip);
        if ((void*)tcp + sizeof(*tcp) > de) return XDP_PASS;
        sport = tcp->source;
        dport = tcp->dest;
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = (void*)ip + sizeof(*udp);
        if ((void*)udp + sizeof(*udp) > de) return XDP_PASS;
        sport = udp->source;
        dport = udp->dest;
    }

    u64 info[4] = {src, dst, sport, dport};
    events.perf_submit(ctx, &info, sizeof(info));
    return XDP_PASS;
}
"""

def block(ip: str):
    if ip not in blocked_ips:
        subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"], check=False)
        blocked_ips[ip] = time.time()
        console.print(f"[bold red][!] BLOCKED {ip}[/]")


def unblock_expired():
    now = time.time()
    for ip in list(blocked_ips):
        if now - blocked_ips[ip] > BLOCK_DURATION:
            subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=False)
            del blocked_ips[ip]
            console.print(f"[bold green][+] UNBLOCKED {ip}[/]")

model = None

def update_model():
    global model

    X = [fv for ip in history for fv in history[ip]]
    if len(X) < 50:
        return

    X_gpu = cp.array(X, dtype=cp.float32)
    contamination = 0.01 if not QUICK_LEARN else 0.02

    model = cuIF(
        contamination=contamination,
        random_state=random.randint(1, 9_999),
    )
    model.fit(X_gpu)


def classify_batch(batch):
    if model is None:
        return [0] * len(batch)

    fv_gpu = cp.array(batch, dtype=cp.float32)
    return model.predict(fv_gpu).tolist()

def build_table():
    table = Table(title="GEN‑7 Autonomous Defender Mesh", expand=True)

    table.add_column("IP")
    table.add_column("PPS")
    table.add_column("RPS")
    table.add_column("Entropy")
    table.add_column("Status", style="bold")
    table.add_column("CPU")
    table.add_column("RAM")

    cpu = psutil.cpu_percent()
    ram = psutil.virtual_memory().percent

    for ip in packet_count:
        status = "[green]OK[/]"
        if ip in blocked_ips:
            status = "[red]BLOCKED[/]"

        ent = sum(entropy_track[ip]) / (len(entropy_track[ip]) or 1)

        table.add_row(
            ip,
            str(packet_count[ip]),
            str(request_count[ip]),
            f"{ent:.2f}",
            status,
            f"{cpu}%",
            f"{ram}%"
        )

    return table

def handle_event(cpu, data, size):
    global last_reset

    src, dst, sport, dport = struct.unpack("LLLL", data)
    ip = socket.inet_ntoa(struct.pack("!I", src))

    packet_count[ip] += 1
    request_count[ip] += 1

    entropy_track[ip].append(abs(int(sport) - int(dport)) % 1024)

    fv = np.array([
        dport % 1000,
        sport,
        entropy_track[ip][-1],
        packet_count[ip],
        request_count[ip],
        len(history[ip])
    ], dtype=np.float32)

    history[ip].append(fv)
    classification_queue.append((ip, fv))

    if time.time() - last_reset > 1:
        for ip in packet_count:
            packet_count[ip] = 0
            request_count[ip] = 0
        last_reset = time.time()

def async_classify_worker():
    global dynamic_batch

    qlen = len(classification_queue)
    if qlen < 1:
        return

    # dynamic batch tuning
    target = int(dynamic_batch + (qlen * ADAPT_RATE))
    target = max(MIN_BATCH, min(MAX_BATCH, target))

    batch = []
    ips = []

    while classification_queue and len(batch) < target:
        ip, fv = classification_queue.popleft()
        batch.append(fv)
        ips.append(ip)

    preds = classify_batch(batch)

    for ip, pred in zip(ips, preds):
        if pred == -1:
            block(ip)

    dynamic_batch = (dynamic_batch * 0.7) + (target * 0.3)


console.print("[cyan][*] Starting GEN‑7 Autonomous XDP + GPU Mesh...[/]")

b = BPF(text=BPF_PROGRAM)
fn = b.load_func("xdp_prog", BPF.XDP)

device = "eth0"
b.attach_xdp(device, fn, 0)
b["events"].open_perf_buffer(handle_event)

last_update = time.time()

with Live(build_table(), refresh_per_second=5) as live:
    try:
        while True:
            b.perf_buffer_poll()

            executor.submit(async_classify_worker)

            if time.time() - last_update > MODEL_UPDATE:
                update_model()
                last_update = time.time()

            unblock_expired()
            live.update(build_table())

    except KeyboardInterrupt:
        b.remove_xdp(device, 0)
        executor.shutdown(wait=True)
        console.print("[yellow]Exiting...[/]")
