"""
AgentSentinel Phase 0.5: Network Egress Security & Filtering Layer.
Enforces domain allowlists, blocks known exfiltration endpoints, validates destination
protocols/ports, and detects suspicious egress attempts.
NOTE: This is an application-level runtime control plane, designed to integrate with
container networking and kernel-level egress firewalls.
"""

import ipaddress
import re
from typing import List, Optional, Tuple
from urllib.parse import urlparse
from app.core.logger import logger
from app.execution.config import execution_config


class NetworkEgressGuard:
    """
    Application-level network egress control.
    Mediates tool requests involving outbound network access, web queries,
    and HTTP/HTTPS connections.
    """

    def __init__(
        self,
        allowed_domains: Optional[List[str]] = None,
        blocked_domains: Optional[List[str]] = None,
    ):
        self.allowed_domains = allowed_domains or execution_config.ALLOWED_SEARCH_DOMAINS
        self.blocked_domains = blocked_domains or execution_config.BLOCKED_EGRESS_PATTERNS

    def extract_host(self, target: str) -> str:
        """Extracts normalized hostname or IP from target URL or host string."""
        target = target.strip()
        if "://" in target:
            parsed = urlparse(target)
            host = parsed.hostname or ""
        else:
            # Format like 'example.com:443' or 'example.com' or search query
            parts = target.split("/")[0].split(":")
            host = parts[0]
        return host.lower().strip()

    def is_ip_address(self, host: str) -> bool:
        """Checks if host is an IPv4 or IPv6 address."""
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def validate_egress(
        self,
        target_destination: str,
        network_allowed: bool = False,
        custom_allowlist: Optional[List[str]] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Validates whether outbound communication to target_destination is permitted.
        Returns (is_allowed, failure_reason).
        """
        if not target_destination:
            return False, "EMPTY_DESTINATION: No network destination provided."

        # 1. Check if sandbox profile permits network at all
        if not network_allowed:
            return False, "NETWORK_EGRESS_PROHIBITED: Tool execution sandbox has network access disabled."

        host = self.extract_host(target_destination)

        # 2. Block direct IP literals by default (common in command-and-control & exfiltration)
        if self.is_ip_address(host):
            # Check for cloud metadata service (169.254.169.254) or localhost
            if host == "169.254.169.254" or host.startswith("127.") or host == "::1":
                return False, f"METADATA_EGRESS_BLOCKED: Connection to internal or cloud metadata IP '{host}' is strictly prohibited."
            return False, f"RAW_IP_EGRESS_BLOCKED: Outbound connections to raw IP literals ('{host}') are prohibited."

        # 3. Check blocked exfiltration destinations (webhook.site, pastebin, etc.)
        for blocked in self.blocked_domains:
            if blocked.lower() in target_destination.lower() or blocked.lower() == host:
                return False, f"EXFILTRATION_ENDPOINT_BLOCKED: Destination matches known data exfiltration pattern '{blocked}'."

        # 4. Check domain allowlist
        allowlist = custom_allowlist or self.allowed_domains
        is_allowed = False
        for allowed in allowlist:
            allowed_clean = allowed.lower().strip()
            if host == allowed_clean or host.endswith(f".{allowed_clean}"):
                is_allowed = True
                break

        if not is_allowed:
            return False, f"UNAUTHORIZED_DOMAIN_BLOCKED: Destination '{host}' is not in the authorized network allowlist."

        return True, None


default_network_guard = NetworkEgressGuard()
