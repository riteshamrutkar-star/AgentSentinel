"""
AgentSentinel Phase 0.9: Distributed Concurrency & Performance Benchmark.
Evaluates:
1. Multi-threaded concurrent interceptor throughput and latency percentiles (p50, p95, p99).
2. Distributed mutual exclusion lock lease contention, acquisition latencies, and mutual exclusion correctness.
3. Distributed sliding-window rate limiter quota synchronization across simulated concurrent workers.
4. Scoped idempotency engine deduplication efficiency and zero-duplicate execution guarantees under concurrent replay storms.

Exports results to reports/distributed_benchmark_v0.9.json for publication and CI verification.
"""

import argparse
import concurrent.futures
import json
import os
import sys
import time
import uuid
from typing import Any, Dict, List, Tuple

# Ensure backend is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.distributed.state import LocalStateBackend, get_state_backend
from app.distributed.lock import DistributedLock
from app.distributed.idempotency import IdempotencyManager, IdempotencyConflictError
from app.core.ratelimit import RateLimiter
from app.interceptor.proxy import intercept_tool_call
from app.interceptor.schema import ToolCallRequest
from app.db.session import SessionLocal


def benchmark_interceptor_concurrency(concurrency: int = 10, total_requests: int = 200) -> Dict[str, Any]:
    """Measures multi-threaded concurrent request throughput and latency distributions."""
    print(f"[*] Benchmarking Interceptor Concurrency (Workers={concurrency}, Total Requests={total_requests})...")
    latencies: List[float] = []

    def single_intercept(i: int) -> float:
        db = SessionLocal()
        try:
            req = ToolCallRequest(
                session_id=f"sess_bench_{i % 5}",
                agent_id=f"agent_worker_{i % concurrency}",
                user_id="benchmark_user",
                tool_name="read_workspace_file",
                arguments={"file_path": f"workspace/file_{i}.txt"},
                action_type="READ",
                namespace="default",
            )
            t0 = time.perf_counter()
            resp = intercept_tool_call(req, db=db)
            t1 = time.perf_counter()
            return (t1 - t0) * 1000.0  # ms
        finally:
            db.close()

    t_start = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(single_intercept, i) for i in range(total_requests)]
        for f in concurrent.futures.as_completed(futures):
            latencies.append(f.result())
    t_end = time.perf_counter()

    total_time = t_end - t_start
    throughput = total_requests / total_time
    latencies.sort()

    p50 = latencies[int(len(latencies) * 0.50)]
    p95 = latencies[int(len(latencies) * 0.95)]
    p99 = latencies[int(len(latencies) * 0.99)]
    mean_lat = sum(latencies) / len(latencies)

    return {
        "workers": concurrency,
        "total_requests": total_requests,
        "total_time_seconds": round(total_time, 3),
        "throughput_req_per_sec": round(throughput, 1),
        "latency_mean_ms": round(mean_lat, 2),
        "latency_p50_ms": round(p50, 2),
        "latency_p95_ms": round(p95, 2),
        "latency_p99_ms": round(p99, 2),
    }


def benchmark_lock_contention(concurrency: int = 8, total_acquisitions: int = 100) -> Dict[str, Any]:
    """Measures distributed lock contention latencies and mutual exclusion correctness."""
    print(f"[*] Benchmarking Lock Contention (Contenders={concurrency}, Operations={total_acquisitions})...")
    backend = LocalStateBackend()
    resource_name = "critical_ledger_table"
    active_critical_section = 0
    max_concurrent_held = 0
    contention_violations = 0
    latencies: List[float] = []

    def acquire_and_hold(op_id: int) -> float:
        nonlocal active_critical_section, max_concurrent_held, contention_violations
        lock = DistributedLock(name=resource_name, backend=backend, lease_seconds=5, timeout_seconds=10.0)
        t0 = time.perf_counter()
        acquired = lock.acquire()
        t1 = time.perf_counter()

        if acquired:
            active_critical_section += 1
            if active_critical_section > max_concurrent_held:
                max_concurrent_held = active_critical_section
            if active_critical_section > 1:
                contention_violations += 1

            # Simulate brief critical section workload
            time.sleep(0.001)

            active_critical_section -= 1
            lock.release()
            return (t1 - t0) * 1000.0
        return -1.0

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(acquire_and_hold, i) for i in range(total_acquisitions)]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res >= 0:
                latencies.append(res)

    latencies.sort()
    mean_lat = sum(latencies) / len(latencies) if latencies else 0.0
    p95 = latencies[int(len(latencies) * 0.95)] if latencies else 0.0

    return {
        "contenders": concurrency,
        "total_acquisitions": total_acquisitions,
        "successful_acquisitions": len(latencies),
        "max_concurrent_in_critical_section": max_concurrent_held,
        "mutual_exclusion_violations": contention_violations,
        "acquisition_latency_mean_ms": round(mean_lat, 2),
        "acquisition_latency_p95_ms": round(p95, 2),
        "correctness": contention_violations == 0 and max_concurrent_held <= 1,
    }


def benchmark_rate_limiter_synchronization(concurrency: int = 10, requests_per_worker: int = 20) -> Dict[str, Any]:
    """Measures sliding-window rate limit quota synchronization under concurrent thread storms."""
    print(f"[*] Benchmarking Sliding-Window Synchronization (Workers={concurrency}, Requests/Worker={requests_per_worker})...")
    backend = LocalStateBackend()
    quota_limit = 50
    limiter = RateLimiter(window_seconds=60, requests_per_minute=quota_limit, backend=backend)

    total_requests = concurrency * requests_per_worker
    allowed_count = 0
    blocked_count = 0

    def send_rate_limited_request(worker_id: int) -> bool:
        # All workers share the same client identity to stress-test quota synchronization
        is_limited, limit, remaining, _ = limiter.is_rate_limited("shared_tenant_client", "/api/v1/intercept")
        return not is_limited

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(send_rate_limited_request, i) for i in range(total_requests)]
        for f in concurrent.futures.as_completed(futures):
            if f.result():
                allowed_count += 1
            else:
                blocked_count += 1

    # Exactly quota_limit requests must be allowed, and remaining blocked
    quota_enforced = allowed_count == quota_limit
    return {
        "workers": concurrency,
        "total_requests": total_requests,
        "configured_quota": quota_limit,
        "allowed_requests": allowed_count,
        "blocked_requests": blocked_count,
        "quota_enforced_strictly": quota_enforced,
        "leakage_count": max(0, allowed_count - quota_limit),
    }


def benchmark_idempotency_deduplication(concurrency: int = 10, total_replays: int = 100) -> Dict[str, Any]:
    """Measures scoped idempotency deduplication latency and validates 0% duplicate execution."""
    print(f"[*] Benchmarking Idempotency Deduplication (Concurrency={concurrency}, Replays={total_replays})...")
    backend = LocalStateBackend()
    mgr = IdempotencyManager(backend=backend)

    shared_key = f"idem_benchmark_{uuid.uuid4().hex[:8]}"
    execution_counter = 0

    def target_mutation() -> Dict[str, Any]:
        nonlocal execution_counter
        execution_counter += 1
        time.sleep(0.002)
        return {"result": "committed", "tx_seq": execution_counter}

    payload = {"account": "reserve_vault", "delta": 1000}
    cached_hits = 0
    latencies: List[float] = []

    def replay_operation(i: int) -> Tuple[bool, float]:
        t0 = time.perf_counter()
        res, is_cached = mgr.execute_idempotent(
            key=shared_key,
            operation="financial_transfer",
            identity="operator_system",
            endpoint="/api/v1/mutate",
            payload=payload,
            fn=target_mutation,
        )
        t1 = time.perf_counter()
        return is_cached, (t1 - t0) * 1000.0

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(replay_operation, i) for i in range(total_replays)]
        for f in concurrent.futures.as_completed(futures):
            is_cached, lat = f.result()
            latencies.append(lat)
            if is_cached:
                cached_hits += 1

    # Exactly 1 real execution, exactly total_replays - 1 cached hits
    latencies.sort()
    p95 = latencies[int(len(latencies) * 0.95)] if latencies else 0.0

    return {
        "concurrency": concurrency,
        "total_requests": total_replays,
        "actual_executions": execution_counter,
        "cached_deduplications": cached_hits,
        "duplicate_execution_rate_pct": 0.0 if execution_counter == 1 else round(((execution_counter - 1) / total_replays) * 100, 2),
        "deduplication_p95_latency_ms": round(p95, 2),
        "zero_duplication_guarantee": execution_counter == 1,
    }


def main():
    parser = argparse.ArgumentParser(description="AgentSentinel Phase 0.9: Distributed Concurrency Benchmark")
    parser.add_argument("--concurrency", type=int, default=10, help="Worker concurrency pool size")
    parser.add_argument("--requests", type=int, default=150, help="Total requests for interceptor benchmark")
    parser.add_argument("--output", default="reports/distributed_benchmark_v0.9.json", help="Export report path")
    args = parser.parse_args()

    print("=" * 80)
    print("AGENTSENTINEL PHASE 0.9 — DISTRIBUTED CONTROL PLANE CONCURRENCY BENCHMARK")
    print("=" * 80)
    print(f"Timestamp    : {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    print(f"Concurrency  : {args.concurrency} worker threads")
    print(f"Environment  : Horizontally Coordinated Multi-Worker Architecture")
    print("-" * 80)

    # 1. Interceptor Concurrency
    interceptor_res = benchmark_interceptor_concurrency(concurrency=args.concurrency, total_requests=args.requests)

    # 2. Distributed Lock Contention
    lock_res = benchmark_lock_contention(concurrency=args.concurrency, total_acquisitions=80)

    # 3. Rate Limiter Synchronization
    ratelimit_res = benchmark_rate_limiter_synchronization(concurrency=args.concurrency, requests_per_worker=15)

    # 4. Idempotency Deduplication
    idempotency_res = benchmark_idempotency_deduplication(concurrency=args.concurrency, total_replays=100)

    report = {
        "benchmark_version": "0.9.0",
        "phase": "v0.9",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "topology": {
            "cluster_mode": "Horizontally Scalable Control Plane",
            "coordination_backend": "DistributedStateBackend (RedisStateBackend / LocalStateBackend)",
            "persistence_layer": "PostgreSQL 17 (Durable Entity Boundaries)",
            "spof_disclosure": "Single Redis coordinator and single PostgreSQL primary",
        },
        "interceptor_throughput": interceptor_res,
        "distributed_locking": lock_res,
        "sliding_window_rate_limiting": ratelimit_res,
        "idempotency_deduplication": idempotency_res,
    }

    # Print Summary Table
    print("\n" + "=" * 80)
    print("BENCHMARK SUMMARY RESULTS")
    print("=" * 80)
    print(f"1. Concurrent Throughput    : {interceptor_res['throughput_req_per_sec']} req/s (p95: {interceptor_res['latency_p95_ms']} ms, p99: {interceptor_res['latency_p99_ms']} ms)")
    print(f"2. Lock Mutual Exclusion    : {'PASS (0 violations)' if lock_res['correctness'] else 'FAIL'} (p95: {lock_res['acquisition_latency_p95_ms']} ms)")
    print(f"3. Sliding-Window Quota     : {'PASS (Strict 50/50 enforced)' if ratelimit_res['quota_enforced_strictly'] else 'FAIL'} (Leakage: {ratelimit_res['leakage_count']})")
    print(f"4. Idempotency Replay Storm : {'PASS (0% duplicates)' if idempotency_res['zero_duplication_guarantee'] else 'FAIL'} (p95: {idempotency_res['deduplication_p95_latency_ms']} ms)")
    print("=" * 80)

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Benchmark report saved to: {args.output}\n")


if __name__ == "__main__":
    main()
