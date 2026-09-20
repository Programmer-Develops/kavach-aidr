#!/usr/bin/env python
"""
start_kavach.py -- One-command KAVACH-AIDR launcher with Cloudflare Tunnel

Usage:
    python start_kavach.py

What it does:
    1. Starts the KAVACH-AIDR Streamlit dashboard on localhost:8501
    2. Starts a Cloudflare Tunnel and exposes it to the internet
    3. Prints the public URL to share with your teacher / reviewer

Stop with Ctrl+C -- both processes shut down cleanly.
"""

import subprocess
import sys
import time
import re
import signal
import io
from pathlib import Path

if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

ROOT = Path(__file__).parent
STREAMLIT_PORT = 8501

CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

BANNER = f"""
{CYAN}{BOLD}
 ██╗  ██╗ █████╗ ██╗   ██╗ █████╗  ██████╗██╗  ██╗
 ██║ ██╔╝██╔══██╗██║   ██║██╔══██╗██╔════╝██║  ██║
 █████╔╝ ███████║██║   ██║███████║██║     ███████║
 ██╔═██╗ ██╔══██║╚██╗ ██╔╝██╔══██║██║     ██╔══██║
 ██║  ██╗██║  ██║ ╚████╔╝ ██║  ██║╚██████╗██║  ██║
 ╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
{RESET}{YELLOW}{BOLD} AIDR -- Autonomous Intelligent Defensive Reasoner{RESET}
{CYAN} Sovereign - Air-Gapped - Indian Armed Forces{RESET}
"""

processes = []

def cleanup(sig=None, frame=None):
    print(f"\n{YELLOW}Shutting down KAVACH-AIDR...{RESET}")
    for p in processes:
        try:
            p.terminate()
        except Exception:
            pass
    print(f"{GREEN}Stopped. Goodbye.{RESET}")
    sys.exit(0)

def check_cloudflared():
    try:
        subprocess.run(["cloudflared", "--version"], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def start_streamlit():
    print(f"{CYAN}[1/2] Starting KAVACH-AIDR dashboard...{RESET}")
    proc = subprocess.Popen(
        [
            sys.executable, "-m", "streamlit", "run",
            str(ROOT / "kavach" / "ui" / "dashboard.py"),
            "--server.port", str(STREAMLIT_PORT),
            "--server.headless", "true",
            "--browser.gatherUsageStats", "false",
        ],
        cwd=str(ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    processes.append(proc)
    time.sleep(4)
    print(f"{GREEN}  Dashboard running on http://localhost:{STREAMLIT_PORT}{RESET}")
    return proc

def start_tunnel():
    print(f"{CYAN}[2/2] Starting Cloudflare Tunnel...{RESET}")
    proc = subprocess.Popen(
        ["cloudflared", "tunnel", "--url", f"http://localhost:{STREAMLIT_PORT}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    processes.append(proc)
    return proc

def watch_for_url(proc):
    url_pattern = re.compile(r"https://[a-z0-9\-]+\.trycloudflare\.com")
    for line in proc.stderr:
        match = url_pattern.search(line)
        if match:
            return match.group(0)
    return None

def main():
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    print(BANNER)

    if not check_cloudflared():
        print(f"{RED}cloudflared not found.{RESET}")
        print(f"{YELLOW}Install it with:{RESET}")
        print("  winget install Cloudflare.cloudflared")
        print("\nThen run this script again.")
        sys.exit(1)

    start_streamlit()
    tunnel_proc = start_tunnel()

    print(f"\n{YELLOW}Waiting for tunnel URL (10-15 seconds)...{RESET}")
    public_url = watch_for_url(tunnel_proc)

    if public_url:
        print(f"""
{GREEN}{BOLD}{"="*60}
  KAVACH-AIDR IS LIVE
{"="*60}{RESET}

{BOLD}  Public URL:{RESET}
  {CYAN}{BOLD}{public_url}{RESET}

{BOLD}  Share this link with your teacher / reviewer.{RESET}
  They can open it in any browser, anywhere.

{YELLOW}  Press Ctrl+C to stop when done.{RESET}
{GREEN}{"="*60}{RESET}
""")
    else:
        print(f"{RED}Could not get tunnel URL. Check cloudflared installation.{RESET}")
        cleanup()

    try:
        tunnel_proc.wait()
    except KeyboardInterrupt:
        cleanup()

if __name__ == "__main__":
    main()
