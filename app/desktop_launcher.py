"""
BlueLine desktop launcher.

Starts the local Flask engine (bound to 127.0.0.1 only) and opens it in a
native desktop window via `pywebview`. This is the real "desktop app"
entry point, and it degrades gracefully:

  - If `pywebview` is installed (pip install pywebview): opens a native
    OS window (WebView2 on Windows, WebKitGTK on Linux, Cocoa WebView on
    macOS). This is what `packaging/build_windows.bat` bundles into the
    .exe.
  - If `pywebview` is NOT installed: falls back to opening your default
    browser pointed at the local server. Still fully functional, just not
    a standalone window.

Why this two-tier approach: the sandbox this project was built in had no
route to install pywebview (curated package index, no network to PyPI's
full catalog for that package) or PyInstaller, so neither could be
installed *or tested* here. Rather than claim a native window that was
never verified, this launcher is written to work either way and tells
you plainly which mode it's running in.
"""

from __future__ import annotations

import socket
import sys
import threading
import time
import webbrowser

HOST = "127.0.0.1"
PORT = 8642


def _port_is_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex((HOST, port)) != 0


def _wait_for_server(port: int, timeout: float = 10.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex((HOST, port)) == 0:
                return True
        time.sleep(0.1)
    return False


def _start_server_in_background():
    from app.api_server import app as flask_app
    threading.Thread(
        target=lambda: flask_app.run(host=HOST, port=PORT, debug=False, threaded=True, use_reloader=False),
        daemon=True,
    ).start()


def main():
    if not _port_is_free(PORT):
        print(f"Port {PORT} is already in use — assuming a BlueLine server is already running there.")
    else:
        print("Starting BlueLine engine...")
        _start_server_in_background()
        if not _wait_for_server(PORT):
            print("ERROR: BlueLine engine did not start in time.", file=sys.stderr)
            sys.exit(1)

    url = f"http://{HOST}:{PORT}/"

    try:
        import webview  # pywebview
        print("Opening BlueLine in a native window (pywebview)...")
        webview.create_window("BlueLine — Security & Reliability Assessment", url,
                               width=1360, height=860, min_size=(1000, 700))
        webview.start()
    except ImportError:
        print("pywebview is not installed — opening BlueLine in your default browser instead.")
        print("For a native desktop window, run:  pip install pywebview")
        webbrowser.open(url)
        print(f"BlueLine is running at {url}  (Ctrl+C here to stop the engine)")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping BlueLine.")


if __name__ == "__main__":
    main()
