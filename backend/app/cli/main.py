"""
AgentSentinel v1.0: Command-Line Interface (CLI).
Lightweight CLI for operational inspection, health verification, and policy auditing.
Communicates strictly via the public AgentSentinel Control Plane REST API.
Contains zero duplicate security evaluation logic.
"""

import argparse
import json
import os
import sys
from typing import Any, Dict, Optional
import httpx


DEFAULT_SERVER_URL = os.getenv("AGENTSENTINEL_SERVER_URL", "http://localhost:8000")
DEFAULT_API_KEY = os.getenv("AGENTSENTINEL_API_KEY", "")


def get_client(base_url: str, api_key: str, timeout: float = 10.0) -> httpx.Client:
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "AgentSentinel-CLI/1.0.0",
    }
    if api_key:
        headers["X-API-Key"] = api_key
        headers["Authorization"] = f"Bearer {api_key}"
    return httpx.Client(base_url=base_url.rstrip("/"), headers=headers, timeout=timeout)


def cmd_health(args: argparse.Namespace) -> int:
    """Inspects control plane health and readiness status."""
    client = get_client(args.server, args.api_key)
    try:
        res = client.get("/health/ready")
        if res.status_code == 200:
            data = res.json()
            print("[+] AgentSentinel Control Plane: HEALTHY (200 OK)")
            print(f"    Application:  {data.get('app_name', 'AgentSentinel')} v{data.get('version', '1.0.0')}")
            print(f"    Environment:  {data.get('environment', 'unknown')}")
            checks = data.get("checks", {})
            print(f"    PostgreSQL:   {checks.get('database', 'unknown')}")
            print(f"    Redis:        {checks.get('redis', 'unknown')}")
            print(f"    Migrations:   {checks.get('migrations', 'unknown')}")
            return 0
        else:
            print(f"[-] Health Check Failed: HTTP {res.status_code} - {res.text}")
            return 1
    except Exception as e:
        print(f"[-] Connection Error: Could not reach AgentSentinel at {args.server}: {e}")
        return 2


def cmd_auth(args: argparse.Namespace) -> int:
    """Validates operator identity credentials against the control plane."""
    client = get_client(args.server, args.api_key)
    try:
        res = client.get("/api/v1/auth/me")
        if res.status_code == 200:
            data = res.json()
            print("[+] Identity Authentication Verified:")
            print(f"    Identity ID:       {data.get('identity_id')}")
            print(f"    Principal Name:    {data.get('name')}")
            print(f"    Role:              {data.get('role')}")
            print(f"    Auth Method:       {data.get('auth_method')}")
            print(f"    Allowed Namespaces:{data.get('allowed_namespaces')}")
            return 0
        else:
            print(f"[-] Authentication Failed: HTTP {res.status_code} - {res.text}")
            return 1
    except Exception as e:
        print(f"[-] Connection Error: {e}")
        return 2


def cmd_namespaces(args: argparse.Namespace) -> int:
    """Lists active tenant security namespaces and durability boundaries."""
    client = get_client(args.server, args.api_key)
    try:
        res = client.get("/api/v1/distributed/status")
        if res.status_code == 200:
            data = res.json()
            ns_list = data.get("namespaces", {}).get("active_namespaces", [])
            print("[+] Active Durable Namespaces:")
            for ns in ns_list:
                print(f"    • {ns}")
            return 0
        else:
            print(f"[-] Failed to retrieve namespaces: HTTP {res.status_code}")
            return 1
    except Exception as e:
        print(f"[-] Connection Error: {e}")
        return 2


def cmd_agents(args: argparse.Namespace) -> int:
    """Lists registered AI agents in directory."""
    client = get_client(args.server, args.api_key)
    params = {}
    if args.namespace:
        params["namespace"] = args.namespace
    try:
        res = client.get("/api/v1/agents", params=params)
        if res.status_code == 200:
            agents = res.json()
            print(f"[+] Registered Agents ({len(agents)} total):")
            for a in agents:
                print(f"    • [{a.get('status')}] {a.get('agent_id')} ({a.get('role')}) - Trust: {a.get('trust_level')} (Namespace: {a.get('namespace', 'default')})")
            return 0
        else:
            print(f"[-] Failed to retrieve agents: HTTP {res.status_code} - {res.text}")
            return 1
    except Exception as e:
        print(f"[-] Connection Error: {e}")
        return 2


def cmd_policies(args: argparse.Namespace) -> int:
    """Lists active RBAC/ABAC security policy rules."""
    client = get_client(args.server, args.api_key)
    try:
        res = client.get("/api/v1/policy/rules")
        if res.status_code == 200:
            rules = res.json()
            print(f"[+] Active Policy Rules ({len(rules)} total):")
            for r in rules:
                print(f"    [{r.get('priority', 0):02d}] {r.get('rule_id')} -> {r.get('policy_result')} ({r.get('name')})")
            return 0
        else:
            print(f"[-] Failed to retrieve policies: HTTP {res.status_code}")
            return 1
    except Exception as e:
        print(f"[-] Connection Error: {e}")
        return 2


def cmd_alerts(args: argparse.Namespace) -> int:
    """Lists operational security alerts."""
    client = get_client(args.server, args.api_key)
    headers = {}
    if args.namespace:
        headers["X-Namespace"] = args.namespace
    try:
        res = client.get("/api/v1/alerts", headers=headers)
        if res.status_code == 200:
            alerts = res.json()
            print(f"[+] Security Alerts ({len(alerts)} found):")
            for alt in alerts:
                print(f"    • [{alt.get('severity')}] {alt.get('alert_id')} - {alt.get('title')} ({alt.get('status')})")
            return 0
        else:
            print(f"[-] Failed to retrieve alerts: HTTP {res.status_code} - {res.text}")
            return 1
    except Exception as e:
        print(f"[-] Connection Error: {e}")
        return 2


def cmd_events(args: argparse.Namespace) -> int:
    """Lists recent audit events."""
    client = get_client(args.server, args.api_key)
    params = {"limit": args.limit}
    try:
        res = client.get("/api/v1/audit/events", params=params)
        if res.status_code == 200:
            events = res.json()
            print(f"[+] Audit Events (Last {len(events)}):")
            for ev in events:
                print(f"    • {ev.get('timestamp')} | {ev.get('event_id')} | {ev.get('tool_name')} | Decision: {ev.get('decision_result')}")
            return 0
        else:
            print(f"[-] Failed to retrieve events: HTTP {res.status_code} - {res.text}")
            return 1
    except Exception as e:
        print(f"[-] Connection Error: {e}")
        return 2


def cmd_benchmark(args: argparse.Namespace) -> int:
    """Displays benchmark metrics from control plane."""
    client = get_client(args.server, args.api_key)
    try:
        res = client.get("/api/v1/distributed/metrics")
        if res.status_code == 200:
            data = res.json()
            print("[+] AgentSentinel Benchmark Telemetry:")
            print(json.dumps(data, indent=2))
            return 0
        else:
            print(f"[-] Benchmark query failed: HTTP {res.status_code}")
            return 1
    except Exception as e:
        print(f"[-] Connection Error: {e}")
        return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentsentinel",
        description="AgentSentinel v1.0 CLI: Unified AI-Agent Security Control Plane Operator Tool",
    )
    parser.add_argument("--server", default=DEFAULT_SERVER_URL, help="AgentSentinel server URL (default: http://localhost:8000)")
    parser.add_argument("--api-key", default=DEFAULT_API_KEY, help="Operator API key (env: AGENTSENTINEL_API_KEY)")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # health
    subparsers.add_parser("health", help="Check control plane health and readiness")

    # auth
    subparsers.add_parser("auth", help="Verify current API key identity and permissions")

    # namespaces
    subparsers.add_parser("namespaces", help="List active durable security namespaces")

    # agents
    p_agents = subparsers.add_parser("agents", help="List registered AI agents")
    p_agents.add_argument("--namespace", help="Filter by namespace")

    # policies
    subparsers.add_parser("policies", help="List active security policy rules")

    # alerts
    p_alerts = subparsers.add_parser("alerts", help="List operational security alerts")
    p_alerts.add_argument("--namespace", help="Filter by namespace")

    # events
    p_events = subparsers.add_parser("events", help="List recent audit log events")
    p_events.add_argument("--limit", type=int, default=20, help="Maximum events to display")

    # benchmark
    subparsers.add_parser("benchmark", help="Display benchmark telemetry metrics")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "health": cmd_health,
        "auth": cmd_auth,
        "namespaces": cmd_namespaces,
        "agents": cmd_agents,
        "policies": cmd_policies,
        "alerts": cmd_alerts,
        "events": cmd_events,
        "benchmark": cmd_benchmark,
    }

    fn = dispatch.get(args.command)
    if fn:
        code = fn(args)
        sys.exit(code)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
