"""
AgentSentinel Developer SDK: Typed Client.
Provides synchronous and asynchronous clients communicating with the AgentSentinel Control Plane.

ARCHITECTURAL GUARANTEE:
This client contains ZERO local policy evaluation logic.
All security decisions, risk intelligence, delegations, and audit records
are strictly processed by the authoritative AgentSentinel Control Plane.
"""

from typing import Any, Dict, List, Optional
import httpx

from .exceptions import (
    AgentSentinelError,
    AuthenticationError,
    AuthorizationError,
    ApprovalPendingError,
    ConflictError,
    ConnectionError,
    RateLimitExceededError,
    SecurityBlockedError,
)


class AgentSentinelClient:
    """
    Synchronous HTTP client for interacting with the AgentSentinel Control Plane.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        api_key: Optional[str] = None,
        bearer_token: Optional[str] = None,
        default_namespace: str = "default",
        namespace: Optional[str] = None,
        timeout: float = 10.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.default_namespace = namespace or default_namespace
        self.timeout = timeout
        self.api_key = api_key
        self.bearer_token = bearer_token

        headers = {
            "Content-Type": "application/json",
            "X-Namespace": self.default_namespace,
        }
        if api_key:
            headers["X-API-Key"] = api_key
            headers["Authorization"] = f"Bearer {api_key}"
        elif bearer_token:
            headers["Authorization"] = f"Bearer {bearer_token}"

        self._client = httpx.Client(
            base_url=self.base_url,
            headers=headers,
            timeout=self.timeout,
        )

    def _handle_response(self, response: httpx.Response) -> Dict[str, Any]:
        """Maps HTTP status codes to typed SDK exceptions."""
        if response.status_code == 401:
            raise AuthenticationError(f"Authentication failed: {response.text}")
        elif response.status_code == 403:
            raise AuthorizationError(f"Access denied: {response.text}")
        elif response.status_code == 409:
            raise ConflictError(f"Conflict: {response.text}")
        elif response.status_code == 429:
            retry_after = int(response.headers.get("Retry-After", "60"))
            raise RateLimitExceededError(
                f"Rate limit quota exceeded. Retry after {retry_after}s.",
                retry_after_seconds=retry_after,
            )
        elif response.status_code >= 500:
            raise ConnectionError(f"Control plane server error ({response.status_code}): {response.text}")

        try:
            return response.json()
        except Exception:
            return {"raw_text": response.text}

    def intercept(
        self,
        agent_id: str,
        session_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
        user_id: str = "default_user",
        role: str = "default_agent",
        framework_name: str = "Python-SDK",
        namespace: Optional[str] = None,
        target_resource: Optional[str] = None,
        action_type: str = "EXECUTE",
        task_summary: str = "",
        delegation_id: Optional[str] = None,
        raise_on_blocked: bool = True,
        raise_on_block: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Submits a tool call to AgentSentinel for pre-execution interception and auditing.
        If raise_on_blocked is True, raises SecurityBlockedError on BLOCK and ApprovalPendingError on REQUIRE_APPROVAL.
        """
        should_raise = raise_on_blocked if raise_on_block is None else raise_on_block
        payload = {
            "agent_id": agent_id,
            "session_id": session_id,
            "user_id": user_id,
            "tool_name": tool_name,
            "arguments": arguments,
            "role": role,
            "framework_name": framework_name,
            "namespace": namespace or self.default_namespace,
            "target_resource": target_resource or "",
            "action_type": action_type,
            "task_summary": task_summary,
            "delegation_id": delegation_id,
        }

        headers = {
            "X-Namespace": namespace or self.default_namespace,
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
            headers["X-API-Key"] = self.api_key
        elif self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"

        try:
            res = self._client.post("/api/v1/intercept", json=payload, headers=headers)
            data = self._handle_response(res)
        except httpx.RequestError as e:
            raise ConnectionError(f"Failed to communicate with AgentSentinel control plane: {e}")

        decision = data.get("decision", "BLOCK")
        reason = data.get("reason") or data.get("decision_reason") or "Tool execution blocked by security policy."
        if should_raise:
            if decision == "BLOCK":
                raise SecurityBlockedError(
                    message=reason,
                    event_id=data.get("event_id"),
                    decision_reason=reason,
                    verdict="BLOCK",
                    details=data,
                )
            elif decision == "REQUIRE_APPROVAL":
                raise ApprovalPendingError(
                    message="Tool invocation paused: requires human review and authorization.",
                    event_id=data.get("event_id"),
                )

        return data

    def submit_execution(
        self,
        session_id: str,
        agent_id: str,
        tool_name: str,
        arguments: Optional[Dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
        namespace: Optional[str] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Submits a tool execution with optional Idempotency-Key header."""
        payload = {
            "session_id": session_id,
            "agent_id": agent_id,
            "tool_name": tool_name,
            "arguments": arguments or {},
            "namespace": namespace or self.default_namespace,
            **kwargs,
        }
        headers = {}
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        if namespace or self.default_namespace:
            headers["X-Namespace"] = namespace or self.default_namespace
        res = self._client.post("/api/v1/execution/submit", json=payload, headers=headers)
        return self._handle_response(res)

    def register_agent(
        self,
        agent_id: str,
        name: str,
        capabilities: Optional[List[str]] = None,
        trust_level: str = "STANDARD",
        role: str = "default_agent",
        namespace: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Registers an AI agent identity in the AgentSentinel registry."""
        payload = {
            "agent_id": agent_id,
            "name": name,
            "capabilities": capabilities or [],
            "trust_level": trust_level,
            "role": role,
            "namespace": namespace or self.default_namespace,
        }
        res = self._client.post("/api/v1/multiagent/agents", json=payload)
        return self._handle_response(res)

    def get_agent(self, agent_id: str) -> Dict[str, Any]:
        """Retrieves agent registration details and trust tier."""
        res = self._client.get(f"/api/v1/multiagent/agents/{agent_id}")
        return self._handle_response(res)

    def list_approvals(self, status: str = "PENDING") -> List[Dict[str, Any]]:
        """Lists pending action approval requests."""
        res = self._client.get("/api/v1/audit/approvals", params={"status": status})
        data = self._handle_response(res)
        return data if isinstance(data, list) else data.get("approvals", [])

    def resolve_approval(
        self,
        approval_id: str,
        decision: str,
        reviewer: str = "operator",
        notes: str = "",
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Resolves a pending approval with APPROVE or REJECT verdict. Supports Idempotency-Key."""
        payload = {"decision": decision, "reviewer": reviewer, "notes": notes}
        headers = {}
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key

        res = self._client.post(
            f"/api/v1/audit/approvals/{approval_id}/resolve",
            json=payload,
            headers=headers,
        )
        return self._handle_response(res)

    def get_health(self) -> Dict[str, Any]:
        """Returns health probe status."""
        res = self._client.get("/health/live")
        return self._handle_response(res)

    def close(self) -> None:
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class AsyncAgentSentinelClient:
    """
    Asynchronous HTTP client for interacting with the AgentSentinel Control Plane.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        api_key: Optional[str] = None,
        bearer_token: Optional[str] = None,
        default_namespace: str = "default",
        namespace: Optional[str] = None,
        timeout: float = 10.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.default_namespace = namespace or default_namespace
        self.timeout = timeout

        headers = {
            "Content-Type": "application/json",
            "X-Namespace": self.default_namespace,
        }
        if api_key:
            headers["X-API-Key"] = api_key
        elif bearer_token:
            headers["Authorization"] = f"Bearer {bearer_token}"

        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            headers=headers,
            timeout=self.timeout,
        )

    async def _handle_response(self, response: httpx.Response) -> Dict[str, Any]:
        if response.status_code == 401:
            raise AuthenticationError(f"Authentication failed: {response.text}")
        elif response.status_code == 403:
            raise AuthorizationError(f"Access denied: {response.text}")
        elif response.status_code == 409:
            raise ConflictError(f"Conflict: {response.text}")
        elif response.status_code == 429:
            retry_after = int(response.headers.get("Retry-After", "60"))
            raise RateLimitExceededError(
                f"Rate limit quota exceeded. Retry after {retry_after}s.",
                retry_after_seconds=retry_after,
            )
        elif response.status_code >= 500:
            raise ConnectionError(f"Control plane server error ({response.status_code}): {response.text}")

        try:
            return response.json()
        except Exception:
            return {"raw_text": response.text}

    async def intercept(
        self,
        agent_id: str,
        session_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
        user_id: str = "default_user",
        role: str = "default_agent",
        framework_name: str = "Python-SDK-Async",
        namespace: Optional[str] = None,
        target_resource: Optional[str] = None,
        action_type: str = "EXECUTE",
        task_summary: str = "",
        delegation_id: Optional[str] = None,
        raise_on_blocked: bool = True,
        raise_on_block: Optional[bool] = None,
    ) -> Dict[str, Any]:
        should_raise = raise_on_blocked if raise_on_block is None else raise_on_block
        payload = {
            "agent_id": agent_id,
            "session_id": session_id,
            "user_id": user_id,
            "tool_name": tool_name,
            "arguments": arguments,
            "role": role,
            "framework_name": framework_name,
            "namespace": namespace or self.default_namespace,
            "target_resource": target_resource or "",
            "action_type": action_type,
            "task_summary": task_summary,
            "delegation_id": delegation_id,
        }

        headers = {}
        if namespace:
            headers["X-Namespace"] = namespace

        try:
            res = await self._client.post("/api/v1/intercept", json=payload, headers=headers)
            data = await self._handle_response(res)
        except httpx.RequestError as e:
            raise ConnectionError(f"Failed to communicate with AgentSentinel control plane: {e}")

        decision = data.get("decision", "BLOCK")
        if should_raise:
            if decision == "BLOCK":
                raise SecurityBlockedError(
                    message=data.get("decision_reason", "Tool execution blocked by security policy."),
                    event_id=data.get("event_id"),
                    decision_reason=data.get("decision_reason"),
                    verdict="BLOCK",
                    details=data,
                )
            elif decision == "REQUIRE_APPROVAL":
                raise ApprovalPendingError(
                    message="Tool invocation paused: requires human review and authorization.",
                    event_id=data.get("event_id"),
                )

        return data

    async def submit_execution(
        self,
        session_id: str,
        agent_id: str,
        tool_name: str,
        arguments: Optional[Dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
        namespace: Optional[str] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Submits a tool execution asynchronously with optional Idempotency-Key header."""
        payload = {
            "session_id": session_id,
            "agent_id": agent_id,
            "tool_name": tool_name,
            "arguments": arguments or {},
            "namespace": namespace or self.default_namespace,
            **kwargs,
        }
        headers = {}
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        if namespace or self.default_namespace:
            headers["X-Namespace"] = namespace or self.default_namespace
        res = await self._client.post("/api/v1/execution/submit", json=payload, headers=headers)
        return await self._handle_response(res)

    async def close(self) -> None:
        if hasattr(self._client, "aclose"):
            res = self._client.aclose()
            if hasattr(res, "__await__"):
                await res

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
