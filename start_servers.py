import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BACKEND_CWD = ROOT
FRONTEND_CWD = ROOT / "frontend"


def launch_process(cmd, cwd):
    """Launch a subprocess and return the handle."""
    return subprocess.Popen(cmd, cwd=cwd)


def main():
    # Backend: use the current Python interpreter (already venv-aware when launched from venv)
    backend_cmd = [sys.executable, "api.py"]

    # Frontend: use npm to run the dev server
    frontend_cmd = ["npm.cmd", "run", "dev"]

    print("Starting backend (Flask API)...")
    backend = launch_process(backend_cmd, BACKEND_CWD)

    # Give backend a moment to boot before starting frontend
    time.sleep(1)

    print("Starting frontend (Vite)...")
    frontend = launch_process(frontend_cmd, FRONTEND_CWD)

    print("\nServers started. Press Ctrl+C to stop both.\n")
    print("Backend: http://127.0.0.1:5000/api/health")
    print("Frontend: check Vite output for the URL (usually http://localhost:5173 or 3000)\n")

    try:
        # Wait on backend; if it exits, we'll stop frontend
        backend.wait()
    except KeyboardInterrupt:
        print("\nStopping...\n")
    finally:
        for proc, name in [(backend, "backend"), (frontend, "frontend")]:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                print(f"Stopped {name}.")


if __name__ == "__main__":
    main()
