"""
Tactical Ops-Center Web Server Launcher & Real Research Backend.
Binds to IPv4 127.0.0.1 and executes the actual cryptographic algorithms.
Synchronizes every UI interaction with live terminal logs and SSE event stream.
"""

import os
import socketserver
import sys
import webbrowser

from backend import ResearchHTTPRequestHandler, BACKEND_INSTANCE


def run_server(port: int = 8000):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    web_dir = os.path.join(base_dir, "shamir-web")

    if not os.path.isdir(web_dir):
        print(f"[ERROR] Web directory not found: {web_dir}", flush=True)
        sys.exit(1)

    class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        allow_reuse_address = True
        daemon_threads = True

    # Try requested port or fallback
    httpd = None
    selected_port = port
    for test_port in [port, 8080, 8081, 8888]:
        try:
            httpd = ThreadedTCPServer(("127.0.0.1", test_port), ResearchHTTPRequestHandler)
            selected_port = test_port
            break
        except OSError:
            continue

    if httpd is None:
        print(f"[ERROR] Unable to bind to any port (tried {port}, 8080, 8081, 8888).", flush=True)
        sys.exit(1)

    url_local = f"http://localhost:{selected_port}/"
    url_ip = f"http://127.0.0.1:{selected_port}/"

    print("\n" + "=" * 78, flush=True)
    print("   UAV SWARM OPERATIONS WORKBENCH & REAL RESEARCH BACKEND", flush=True)
    print("   Cryptographic Engine: Mersenne Prime F_p (p = 2^127 - 1) | SRAM PUF", flush=True)
    print("   Protocols: Mode A (Centralized BS) & Mode B (Decentralized Quorum + VSS)", flush=True)
    print("=" * 78, flush=True)
    print(f"   Root Directory: {web_dir}", flush=True)
    print(f"\n   >>> CLICK TO OPEN IN BROWSER:", flush=True)
    print(f"       {url_local}", flush=True)
    print(f"       {url_ip}\n", flush=True)
    print("   [LIVE TERMINAL ACTIVE] All UI actions execute real algorithms and log here in real time.", flush=True)
    print("   (Press Ctrl+C in this terminal to stop)", flush=True)
    print("=" * 78 + "\n", flush=True)

    try:
        webbrowser.open(url_local)
    except Exception:
        pass

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[STOP] Web server stopped by user.", flush=True)
    finally:
        httpd.server_close()


if __name__ == "__main__":
    port_arg = 8000
    if len(sys.argv) > 1:
        try:
            port_arg = int(sys.argv[1])
        except ValueError:
            pass
    run_server(port_arg)
