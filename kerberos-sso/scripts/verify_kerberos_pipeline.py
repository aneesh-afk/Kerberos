"""
Kerberos SSO Demonstration and Pipeline Verification Script

Demonstrates and verifies the entire Kerberos protocol flow:
  Client -> AS (8001) -> TGS (8002) -> Service Server (8003)

Usage:
  python scripts/verify_kerberos_pipeline.py          # Runs in-memory via FastAPI ASGI
  python scripts/verify_kerberos_pipeline.py --live   # Tests running live server ports
"""

import argparse
import base64
import json
import os
import sys
import time
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dotenv import load_dotenv
load_dotenv(PROJECT_ROOT / ".env")


def print_header(title: str):
    print("\n" + "=" * 65)
    print(f"  {title}")
    print("=" * 65)


def print_step(step_num: int, title: str, details: dict = None):
    print(f"\n[Step {step_num}] {title}")
    if details:
        for k, v in details.items():
            if isinstance(v, str) and len(v) > 60:
                v = v[:30] + "..." + v[-20:]
            print(f"    - {k}: {v}")


def run_pipeline(use_live: bool = False):
    print_header("Kerberos SSO Protocol Verification")

    if use_live:
        import requests
        as_base = "http://127.0.0.1:8001"
        tgs_base = "http://127.0.0.1:8002"
        ss_base = "http://127.0.0.1:8003"

        def post_as(path, body):
            r = requests.post(f"{as_base}{path}", json=body)
            return r.status_code, r.json()

        def post_tgs(path, body):
            r = requests.post(f"{tgs_base}{path}", json=body)
            return r.status_code, r.json()

        def post_ss(path, body):
            r = requests.post(f"{ss_base}{path}", json=body)
            return r.status_code, r.json()
    else:
        from fastapi.testclient import TestClient
        import importlib.util

        def load_app(module_path, mod_name):
            spec = importlib.util.spec_from_file_location(mod_name, module_path)
            mod = importlib.util.module_from_spec(spec)
            sys.modules[mod_name] = mod
            spec.loader.exec_module(mod)
            return mod.app

        as_app = load_app(PROJECT_ROOT / "backend" / "kerberos-as" / "main.py", "as_demo")
        tgs_app = load_app(PROJECT_ROOT / "backend" / "kerberos-tgs" / "main.py", "tgs_demo")
        ss_app = load_app(PROJECT_ROOT / "backend" / "service-server" / "main.py", "ss_demo")

        as_client = TestClient(as_app)
        tgs_client = TestClient(tgs_app)
        ss_client = TestClient(ss_app)

        def post_as(path, body):
            r = as_client.post(path, json=body)
            return r.status_code, r.json()

        def post_tgs(path, body):
            r = tgs_client.post(path, json=body)
            return r.status_code, r.json()

        def post_ss(path, body):
            r = ss_client.post(path, json=body)
            return r.status_code, r.json()

    # -----------------------------------------------------------------------
    # Step 1: User authenticates with AS
    # -----------------------------------------------------------------------
    username = "alice"
    password = "password123"
    print_step(1, f"Authenticating user '{username}' against AS", {"username": username})

    status_code, as_res = post_as("/as/authenticate", {"username": username, "password": password})
    assert status_code == 200, f"AS authentication failed ({status_code}): {as_res}"
    print(f"    --> HTTP {status_code} OK")
    print(f"    --> TGT issued (encrypted with AS_TGS_SHARED_KEY): {as_res['tgt'][:35]}...")
    print(f"    --> Client-TGS Session Key generated: {as_res['session_key'][:25]}...")
    tgt = as_res["tgt"]

    # -----------------------------------------------------------------------
    # Step 2: Request Service Ticket from TGS
    # -----------------------------------------------------------------------
    service_id = "service-server"
    now = int(time.time())
    print_step(2, f"Presenting TGT to TGS to request access to '{service_id}'", {
        "service_id": service_id,
        "timestamp": now,
    })

    status_code, tgs_res = post_tgs("/tgs/service-ticket", {
        "tgt": tgt,
        "service_id": service_id,
        "timestamp": now,
    })
    assert status_code == 200, f"TGS service ticket request failed ({status_code}): {tgs_res}"
    print(f"    --> HTTP {status_code} OK")
    print(f"    --> Service Ticket issued (encrypted with TGS_SERVICE_SHARED_KEY): {tgs_res['service_ticket'][:35]}...")
    print(f"    --> Client-Service Session Key generated: {tgs_res['session_key'][:25]}...")
    service_ticket = tgs_res["service_ticket"]

    # -----------------------------------------------------------------------
    # Step 3: Present Service Ticket to Service Server (Group 4)
    # -----------------------------------------------------------------------
    print_step(3, f"Presenting Service Ticket to Service Server", {"service_id": service_id})

    status_code, ss_res = post_ss("/service/access", {
        "service_ticket": service_ticket,
        "timestamp": now,
    })
    assert status_code == 200, f"Service Server access failed ({status_code}): {ss_res}"
    print(f"    --> HTTP {status_code} OK")
    print(f"    --> Granted: {ss_res.get('granted')}")
    print(f"    --> Client: {ss_res.get('client_id')}")
    print(f"    --> Resource: {ss_res.get('resource')}")

    # -----------------------------------------------------------------------
    # Step 4: Security verification — Tampered Ticket
    # -----------------------------------------------------------------------
    print_step(4, "Testing Tamper Protection (Flipping byte in ciphertext)")
    raw_st = bytearray(base64.b64decode(service_ticket))
    raw_st[14] ^= 0xFF
    tampered_st = base64.b64encode(raw_st).decode("utf-8")

    status_code, ss_tamper_res = post_ss("/service/access", {
        "service_ticket": tampered_st,
    })
    print(f"    --> HTTP {status_code} (Expected 401)")
    assert status_code == 401, "Tampered ticket should have been rejected with 401!"
    print(f"    --> Rejection Reason: {ss_tamper_res.get('detail')}")

    # -----------------------------------------------------------------------
    # Step 5: Security verification — Replay Attack Window
    # -----------------------------------------------------------------------
    print_step(5, "Testing Replay Protection (Stale timestamp beyond clock skew)")
    status_code, tgs_stale_res = post_tgs("/tgs/service-ticket", {
        "tgt": tgt,
        "service_id": service_id,
        "timestamp": now - 600,  # 10 minutes old (exceeds 300s clock skew)
    })
    print(f"    --> HTTP {status_code} (Expected 401)")
    assert status_code == 401, "Stale timestamp request should have been rejected with 401!"
    print(f"    --> Rejection Reason: {tgs_stale_res.get('detail')}")

    print_header("ALL KERBEROS PIPELINE CHECKS PASSED SUCCESSFULLY!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kerberos SSO Pipeline Verifier")
    parser.add_argument("--live", action="store_true", help="Run against live HTTP servers on ports 8001, 8002, 8003")
    args = parser.parse_args()

    run_pipeline(use_live=args.live)
