#!/usr/bin/env python
"""
start_kavach.py -- One-command KAVACH-AIDR launcher with Cloudflare Tunnel
Usage:  python start_kavach.py
Stop:   Ctrl+C
"""

import subprocess, sys, time, re, signal, io
from pathlib import Path

if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

ROOT           = Path(__file__).parent
STREAMLIT_PORT = 8501

# Common install locations for cloudflared on Windows
CLOUDFLARED_CANDIDATES = [
    "cloudflared",
    r"C:\Program Files (x86)\cloudflared\cloudflared.exe",
    r"C:\Program Files\cloudflared\cloudflared.exe",
]

CYAN="\033[96m"; GREEN="\033[92m"; YELLOW="\033[93m"; RED="\033[91m"; BOLD="\033[1m"; RESET="\033[0m"

BANNER = f"""
{CYAN}{BOLD}
 ██╗  ██╗ █████╗ ██╗   ██╗ █████╗  ██████╗██╗  ██╗
 ██║ ██╔╝██╔══██╗██║   ██║██╔══██╗██╔════╝██║  ██║
 █████╔╝ ███████║██║   ██║███████║██║     ███████║
 ██╔═██╗ ██╔══██║╚██╗ ██╔╝██╔══██║██║     ██╔══██║
 ██║  ██╗██║  ██║ ╚████╔╝ ██║  ██║╚██████╗██║  ██║
 ╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
{RESET}{YELLOW}{BOLD} AIDR  --  Autonomous Intelligent Defensive Reasoner{RESET}
{CYAN} Sovereign  |  Air-Gapped  |  Indian Armed Forces{RESET}
"""

processes = []

def cleanup(sig=None, frame=None):
    print(f"\n{YELLOW}Shutting down KAVACH-AIDR...{RESET}")
    for p in processes:
        try: p.terminate()
        except: pass
    print(f"{GREEN}Stopped. Goodbye.{RESET}")
    sys.exit(0)

def find_cloudflared():
    for candidate in CLOUDFLARED_CANDIDATES:
        try:
            subprocess.run([candidate, "--version"], capture_output=True, check=True)
            return candidate
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue
    return None

def start_streamlit():
    print(f"{CYAN}[1/2] Starting KAVACH-AIDR dashboard...{RESET}")
    proc = subprocess.Popen(
        [sys.executable, "-m", "streamlit", "run",
         str(ROOT / "kavach" / "ui" / "dashboard.py"),
         "--server.port", str(STREAMLIT_PORT),
         "--server.headless", "true",
         "--browser.gatherUsageStats", "false"],
        cwd=str(ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    processes.append(proc)
    time.sleep(4)
    print(f"{GREEN}  Dashboard running at http://localhost:{STREAMLIT_PORT}{RESET}")

def start_tunnel(cf_bin):
    print(f"{CYAN}[2/2] Opening Cloudflare Tunnel...{RESET}")
    proc = subprocess.Popen(
        [cf_bin, "tunnel", "--url", f"http://localhost:{STREAMLIT_PORT}"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", errors="replace",
    )
    processes.append(proc)
    return proc

def watch_for_url(proc):
    url_re = re.compile(r"https://[a-z0-9\-]+\.trycloudflare\.com")
    for line in proc.stderr:
        m = url_re.search(line)
        if m: return m.group(0)
    return None

def main():
    signal.signal(signal.SIGINT,  cleanup)
    signal.signal(signal.SIGTERM, cleanup)
    print(BANNER)

    cf_bin = find_cloudflared()
    if not cf_bin:
        print(f"{RED}cloudflared not found.{RESET}")
        print(f"Install:  winget install Cloudflare.cloudflared")
        print("Then restart your terminal and run this script again.")
        sys.exit(1)

    start_streamlit()
    tunnel = start_tunnel(cf_bin)

    print(f"\n{YELLOW}Waiting for public URL (10-15 seconds)...{RESET}")
    url = watch_for_url(tunnel)

    if url:
        sep = "=" * 60
        print(f"\n{GREEN}{BOLD}{sep}\n  KAVACH-AIDR IS LIVE\n{sep}{RESET}")
        print(f"\n  {BOLD}Public URL:{RESET}")
        print(f"  {CYAN}{BOLD}{url}{RESET}\n")
        print(f"  {BOLD}Share this with your teacher or reviewer.{RESET}")
        print(f"  Works in any browser, anywhere.\n")
        print(f"  {YELLOW}Press Ctrl+C when done.{RESET}")
        print(f"{GREEN}{sep}{RESET}\n")
    else:
        print(f"{RED}Could not get tunnel URL.{RESET}")
        cleanup()

    try:
        tunnel.wait()
    except KeyboardInterrupt:
        cleanup()

if __name__ == "__main__":
    main()
