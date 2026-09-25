#!/usr/bin/env python3
"""
masprobe — masscan + parallel nmap pipeline for CIDR-scoped recon.

Takes one or more in-scope CIDR ranges, subtracts out-of-scope ranges,
runs masscan for fast port discovery, then runs nmap per-host in parallel
for service/version enumeration. Results stream to stdout as hosts
complete; per-host nmap output is written to <outdir>/nmap/<ip>.{nmap,gnmap,xml}.

Usage:
    masprobe -i 131.152.0.0/16 -x 131.152.122.128/25 -x 131.152.122.192/26
    masprobe -i 10.0.0.0/16,10.1.0.0/16 -x 10.0.5.0/24 -p 80,443,8080
    masprobe -i 131.152.0.0/16 -x 131.152.122.128/25 -r 5000 -j 20

Output layout (per run):
    runs/<timestamp>/
        targets.txt       in-scope CIDRs fed to masscan
        masscan.txt       raw masscan -oL output
        live_hosts.txt    unique IPs with >=1 open port
        open_ports.txt    unique ports found open anywhere
        nmap/<ip>.{nmap,gnmap,xml}   per-host nmap results
        summary.txt       one-line-per-service summary
"""

import argparse
import concurrent.futures
import ipaddress
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

DEFAULT_PORTS = (
    "7,9,13,21,22,23,25,26,37,53,69,79,80,81,88,106,110,111,113,119,123,"
    "135,139,143,144,161,162,179,199,389,427,443,444,445,464,465,500,513,"
    "514,515,543,544,548,554,587,623,631,636,646,873,990,993,995,1025,"
    "1026,1027,1028,1029,1110,1194,1433,1521,1701,1720,1723,1755,1883,"
    "1900,2000,2001,2049,2121,2181,2200,2222,2323,2375,2376,2379,2380,"
    "2717,3000,3001,3002,3128,3260,3268,3269,3306,3389,3986,4040,4190,"
    "4500,4899,5000,5001,5006,5009,5051,5060,5101,5190,5353,5357,5432,"
    "5433,5601,5631,5666,5672,5800,5900,5901,5984,5985,5986,6000,6001,"
    "6080,6081,6082,6379,6443,6646,6817,6818,6819,7070,7077,7474,7687,"
    "7860,8000,8001,8008,8009,8010,8022,8043,8080,8081,8082,8083,8084,"
    "8085,8086,8087,8088,8089,8090,8091,8095,8100,8123,8161,8180,8181,"
    "8188,8200,8280,8282,8443,8444,8500,8501,8502,8529,8773,8774,8775,"
    "8776,8786,8787,8880,8883,8888,8890,8983,9000,9001,9002,9042,9080,"
    "9090,9091,9092,9093,9100,9200,9292,9300,9443,9696,9800,9870,9900,"
    "9999,10000,10050,10250,10255,10256,10443,11211,11434,15672,18080,"
    "18081,26257,27017,27018,28017,28080,32768,49152,49153,49154,49155,"
    "49156,49157,50070,51820,61616"
)
DEFAULT_NMAP_ARGS = "-sV --open --version-light"


# ---------- arguments ----------

def parse_args():
    p = argparse.ArgumentParser(
        prog="masprobe",
        description="masscan + parallel nmap pipeline for CIDR-scoped recon.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("-i", "--include", action="append", required=True,
                   metavar="CIDR",
                   help="In-scope CIDR (repeatable, or comma-separated).")
    p.add_argument("-x", "--exclude", action="append", default=[],
                   metavar="CIDR",
                   help="Out-of-scope CIDR (repeatable, or comma-separated).")
    p.add_argument("-p", "--ports", default=DEFAULT_PORTS,
                   help=f"Ports list. Default: {DEFAULT_PORTS}")
    p.add_argument("-r", "--rate", type=int, default=1000,
                   help="masscan packets/sec. Default: 1000")
    p.add_argument("-j", "--jobs", type=int, default=10,
                   help="Parallel nmap jobs. Default: 10")
    p.add_argument("-o", "--outdir", default=None,
                   help="Output dir. Default: runs/<timestamp>/")
    p.add_argument("--nmap-args", default=DEFAULT_NMAP_ARGS,
                   help=f"Extra nmap args. Default: '{DEFAULT_NMAP_ARGS}'")
    p.add_argument("--skip-masscan", action="store_true",
                   help="Skip masscan, reuse existing masscan.txt.")
    p.add_argument("--skip-nmap", action="store_true",
                   help="Skip nmap stage (discovery only).")
    return p.parse_args()


# ---------- CIDR math ----------

def parse_cidrs(items):
    nets = []
    for item in items:
        for part in item.split(","):
            part = part.strip()
            if part:
                nets.append(ipaddress.ip_network(part, strict=False))
    return nets


def subtract_networks(includes, excludes):
    """Return includes minus excludes, collapsed to a minimal CIDR list.

    CIDR blocks form a laminar family (any two are either disjoint or one
    contains the other), which is what makes this clean.
    """
    result = list(ipaddress.collapse_addresses(includes))
    for ex in excludes:
        new_result = []
        for inc in result:
            if not inc.overlaps(ex):
                new_result.append(inc)
            elif inc == ex or inc.subnet_of(ex):
                pass  # fully excluded
            else:
                # ex is a proper subnet of inc -> split inc around ex
                new_result.extend(inc.address_exclude(ex))
        result = new_result
    return list(ipaddress.collapse_addresses(result))


# ---------- tool runners ----------

def run_masscan(targets_file, ports, rate, out_file):
    cmd = [
        "sudo", "masscan", "-iL", str(targets_file),
        "-p", ports,
        "--rate", str(rate),
        "--wait", "10",
        "-oL", str(out_file),
    ]
    print(f"[*] {' '.join(cmd)}\n", flush=True)
    return subprocess.run(cmd).returncode == 0


def parse_masscan(out_file):
    """Return {ip: set(ports)} parsed from masscan -oL output."""
    hits = {}
    with open(out_file) as f:
        for line in f:
            parts = line.split()
            # -oL format: "open tcp <port> <ip> <timestamp>"
            if len(parts) >= 4 and parts[0] == "open":
                hits.setdefault(parts[3], set()).add(int(parts[2]))
    return hits


def nmap_one(host, ports, nmap_dir, extra_args):
    """Run nmap against a single host on its specific ports."""
    ports_str = ",".join(str(p) for p in sorted(ports))
    outbase = nmap_dir / host
    # -sT: TCP connect scan, works behind NAT (no raw sockets needed)
    cmd = ["nmap", "-sT", "-Pn", "-p", ports_str,
           "-oA", str(outbase)] + extra_args + [host]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return host, proc.stdout


def nmap_parallel(hits, nmap_dir, jobs, extra_args):
    """Run nmap per-host in parallel; print results as they complete."""
    nmap_dir.mkdir(parents=True, exist_ok=True)
    total = len(hits)
    done = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as ex:
        futures = {
            ex.submit(nmap_one, host, ports, nmap_dir, extra_args): host
            for host, ports in hits.items()
        }
        for fut in concurrent.futures.as_completed(futures):
            try:
                host, output = fut.result()
            except Exception as e:
                done += 1
                print(f"\n[{done}/{total}] <error> — {e}", flush=True)
                continue
            done += 1
            open_lines = [l.strip() for l in output.splitlines()
                          if "/tcp" in l and "open" in l]
            print(f"\n[{done}/{total}] {host}  ({len(open_lines)} open)",
                  flush=True)
            for line in open_lines:
                print(f"    {line}", flush=True)


def write_summary(outdir, hits, nmap_dir):
    summary = outdir / "summary.txt"
    with open(summary, "w") as f:
        for host in sorted(hits, key=ipaddress.ip_address):
            nmap_out = nmap_dir / f"{host}.nmap"
            f.write(f"=== {host} ===\n")
            if nmap_out.exists():
                with open(nmap_out) as nf:
                    for line in nf:
                        if "/tcp" in line and "open" in line:
                            f.write(f"  {line.rstrip()}\n")
            f.write("\n")
    print(f"\n[*] Summary written to {summary}")


# ---------- main ----------

def main():
    args = parse_args()

    for tool in ([] if args.skip_masscan else ["masscan"]) + \
                ([] if args.skip_nmap else ["nmap"]):
        if shutil.which(tool) is None:
            sys.exit(f"[!] Required tool not found in PATH: {tool}")

    includes = parse_cidrs(args.include)
    excludes = parse_cidrs(args.exclude)
    scoped = subtract_networks(includes, excludes)

    if not scoped:
        sys.exit("[!] No in-scope addresses after exclusions.")

    total_ips = sum(net.num_addresses for net in scoped)

    print(f"[*] Include CIDRs: {len(includes)}")
    print(f"[*] Exclude CIDRs: {len(excludes)}")
    print(f"[*] Scoped networks: {len(scoped)}  ({total_ips:,} addresses)")
    for net in scoped[:12]:
        print(f"      {net}")
    if len(scoped) > 12:
        print(f"      ... (+{len(scoped) - 12} more)")

    # output dir
    if args.outdir:
        outdir = Path(args.outdir)
    else:
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        outdir = Path("runs") / ts
    outdir.mkdir(parents=True, exist_ok=True)
    print(f"[*] Output dir: {outdir}\n")

    targets_file = outdir / "targets.txt"
    with open(targets_file, "w") as f:
        for net in scoped:
            f.write(f"{net}\n")

    masscan_out = outdir / "masscan.txt"
    if args.skip_masscan:
        if not masscan_out.exists():
            sys.exit(f"[!] --skip-masscan but {masscan_out} doesn't exist")
        print(f"[*] Reusing existing {masscan_out}")
    else:
        run_masscan(targets_file, args.ports, args.rate, masscan_out)

    hits = parse_masscan(masscan_out)
    print(f"\n[*] masscan: {len(hits)} hosts with open ports")

    if not hits:
        print("[!] No open ports found. Done.")
        return

    # convenience files
    with open(outdir / "live_hosts.txt", "w") as f:
        for ip in sorted(hits, key=ipaddress.ip_address):
            f.write(f"{ip}\n")

    all_ports = sorted({p for ports in hits.values() for p in ports})
    with open(outdir / "open_ports.txt", "w") as f:
        f.write("\n".join(str(p) for p in all_ports) + "\n")
    print(f"[*] Unique open ports: {','.join(str(p) for p in all_ports)}")

    if args.skip_nmap:
        print("[*] --skip-nmap set; done.")
        return

    extra_args = args.nmap_args.split() if args.nmap_args else []
    nmap_dir = outdir / "nmap"
    print(f"\n[*] nmap: {len(hits)} hosts, jobs={args.jobs}, "
          f"args='{args.nmap_args}'\n")

    try:
        nmap_parallel(hits, nmap_dir, args.jobs, extra_args)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.", flush=True)

    write_summary(outdir, hits, nmap_dir)
    print(f"[*] Done. Results in {outdir}")


if __name__ == "__main__":
    main()
