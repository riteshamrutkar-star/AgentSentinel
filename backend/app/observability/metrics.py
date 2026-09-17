"""
AgentSentinel Phase 0.8: Prometheus-Compatible Metrics Registry.
Lightweight, thread-safe, pure-Python Prometheus metric collector and text serializer.
Captures HTTP throughput, tool verdicts, execution latencies, and security events.
"""

import threading
import time
from typing import Dict, List, Tuple, Optional


class Metric:
    def __init__(self, name: str, description: str, metric_type: str):
        self.name = name
        self.description = description
        self.metric_type = metric_type
        self._lock = threading.Lock()


class Counter(Metric):
    def __init__(self, name: str, description: str):
        super().__init__(name, description, "counter")
        self._values: Dict[Tuple[Tuple[str, str], ...], float] = {}

    def inc(self, value: float = 1.0, **labels):
        label_key = tuple(sorted(labels.items()))
        with self._lock:
            self._values[label_key] = self._values.get(label_key, 0.0) + value

    def get_samples(self) -> List[Tuple[Dict[str, str], float]]:
        with self._lock:
            return [(dict(k), v) for k, v in self._values.items()]


class Gauge(Metric):
    def __init__(self, name: str, description: str):
        super().__init__(name, description, "gauge")
        self._values: Dict[Tuple[Tuple[str, str], ...], float] = {}

    def set(self, value: float, **labels):
        label_key = tuple(sorted(labels.items()))
        with self._lock:
            self._values[label_key] = float(value)

    def get_samples(self) -> List[Tuple[Dict[str, str], float]]:
        with self._lock:
            return [(dict(k), v) for k, v in self._values.items()]


class Histogram(Metric):
    def __init__(self, name: str, description: str, buckets: Optional[List[float]] = None):
        super().__init__(name, description, "histogram")
        self.buckets = sorted(buckets or [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0])
        self._counts: Dict[Tuple[Tuple[str, str], ...], float] = {}
        self._sums: Dict[Tuple[Tuple[str, str], ...], float] = {}
        self._bucket_counts: Dict[Tuple[Tuple[str, str], ...], Dict[float, float]] = {}

    def observe(self, value: float, **labels):
        label_key = tuple(sorted(labels.items()))
        with self._lock:
            self._counts[label_key] = self._counts.get(label_key, 0.0) + 1.0
            self._sums[label_key] = self._sums.get(label_key, 0.0) + value

            if label_key not in self._bucket_counts:
                self._bucket_counts[label_key] = {b: 0.0 for b in self.buckets}

            for b in self.buckets:
                if value <= b:
                    self._bucket_counts[label_key][b] += 1.0


class PrometheusRegistry:
    """Thread-safe catalog of Prometheus metrics for AgentSentinel."""

    def __init__(self):
        self._metrics: Dict[str, Metric] = {}
        self._init_standard_metrics()

    def _init_standard_metrics(self):
        self.http_requests_total = self.register_counter(
            "agentsentinel_http_requests_total",
            "Total HTTP requests received by endpoint and status code."
        )
        self.http_request_duration_seconds = self.register_histogram(
            "agentsentinel_http_request_duration_seconds",
            "HTTP request latency distribution in seconds."
        )
        self.tool_calls_total = self.register_counter(
            "agentsentinel_tool_calls_total",
            "Total tool execution requests intercepted by final verdict (ALLOW, BLOCK, REQUIRE_APPROVAL)."
        )
        self.policy_violations_total = self.register_counter(
            "agentsentinel_policy_violations_total",
            "Total security policy blocks recorded by policy effect."
        )
        self.behavioral_anomalies_total = self.register_counter(
            "agentsentinel_behavioral_anomalies_total",
            "Total behavioral anomaly escalations by severity level."
        )
        self.execution_attempts_total = self.register_counter(
            "agentsentinel_execution_attempts_total",
            "Total tool execution gateway attempts by status."
        )
        self.delegation_violations_total = self.register_counter(
            "agentsentinel_delegation_violations_total",
            "Total multi-agent delegation policy rejections."
        )
        self.security_alerts_total = self.register_counter(
            "agentsentinel_security_alerts_total",
            "Total operational security alerts raised by severity."
        )
        self.rate_limit_exceeded_total = self.register_counter(
            "agentsentinel_rate_limit_exceeded_total",
            "Total requests rejected by rate limiting."
        )
        self.auth_failures_total = self.register_counter(
            "agentsentinel_auth_failures_total",
            "Total authentication failures on protected endpoints."
        )
        self.database_connected = self.register_gauge(
            "agentsentinel_database_connected",
            "PostgreSQL database connectivity status (1 = connected, 0 = disconnected)."
        )
        self.active_agents = self.register_gauge(
            "agentsentinel_active_agents",
            "Count of currently active registered agent identities."
        )

    def register_counter(self, name: str, description: str) -> Counter:
        c = Counter(name, description)
        self._metrics[name] = c
        return c

    def register_gauge(self, name: str, description: str) -> Gauge:
        g = Gauge(name, description)
        self._metrics[name] = g
        return g

    def register_histogram(self, name: str, description: str, buckets: Optional[List[float]] = None) -> Histogram:
        h = Histogram(name, description, buckets)
        self._metrics[name] = h
        return h

    def export_text(self) -> str:
        """Serializes all metric samples into Prometheus exposition format v0.0.4."""
        lines: List[str] = []
        for name, metric in sorted(self._metrics.items()):
            lines.append(f"# HELP {metric.name} {metric.description}")
            lines.append(f"# TYPE {metric.name} {metric.metric_type}")

            if isinstance(metric, (Counter, Gauge)):
                samples = metric.get_samples()
                if not samples:
                    lines.append(f"{metric.name} 0")
                for labels, val in samples:
                    if labels:
                        label_str = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
                        lines.append(f"{metric.name}{{{label_str}}} {val}")
                    else:
                        lines.append(f"{metric.name} {val}")

            elif isinstance(metric, Histogram):
                with metric._lock:
                    for label_key, count in metric._counts.items():
                        labels = dict(label_key)
                        total_sum = metric._sums.get(label_key, 0.0)
                        buckets_map = metric._bucket_counts.get(label_key, {})

                        cumulative = 0.0
                        for b in metric.buckets:
                            cumulative += buckets_map.get(b, 0.0)
                            b_labels = dict(labels)
                            b_labels["le"] = str(b)
                            b_str = ",".join(f'{k}="{v}"' for k, v in sorted(b_labels.items()))
                            lines.append(f"{metric.name}_bucket{{{b_str}}} {cumulative}")

                        inf_labels = dict(labels)
                        inf_labels["le"] = "+Inf"
                        inf_str = ",".join(f'{k}="{v}"' for k, v in sorted(inf_labels.items()))
                        lines.append(f"{metric.name}_bucket{{{inf_str}}} {count}")

                        base_str = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
                        label_prefix = f"{{{base_str}}}" if base_str else ""
                        lines.append(f"{metric.name}_count{label_prefix} {count}")
                        lines.append(f"{metric.name}_sum{label_prefix} {total_sum}")

        return "\n".join(lines) + "\n"


metrics_registry = PrometheusRegistry()
prometheus_registry = metrics_registry