"""
AgentSentinel Phase 0.9: AI Agent Ecosystem Adapters.
Provides canonical adapters for LangChain, LangGraph, AutoGen, CrewAI, and Semantic Kernel.
"""

from app.adapters.base import (
    AgentSentinelAdapter,
    AdapterStatus,
    CanonicalSecurityRequest,
    CanonicalSecurityResult,
    SecurityBlockedException,
)
from app.adapters.langchain import (
    LangChainAdapter,
    AgentSentinelCallbackHandler,
    AgentSentinelToolWrapper,
    default_langchain_adapter,
)
from app.adapters.langgraph import (
    LangGraphAdapter,
    AgentSentinelNodeInterceptor,
    default_langgraph_adapter,
)
from app.adapters.autogen import (
    AutoGenAdapter,
    AgentSentinelAutoGenInterceptor,
    default_autogen_adapter,
)
from app.adapters.crewai import (
    CrewAIAdapter,
    AgentSentinelCrewAIInterceptor,
    default_crewai_adapter,
)
from app.adapters.semantic_kernel import (
    SemanticKernelAdapter,
    AgentSentinelKernelFilter,
    default_semantic_kernel_adapter,
)

__all__ = [
    "AgentSentinelAdapter",
    "AdapterStatus",
    "CanonicalSecurityRequest",
    "CanonicalSecurityResult",
    "SecurityBlockedException",
    # LangChain
    "LangChainAdapter",
    "AgentSentinelCallbackHandler",
    "AgentSentinelToolWrapper",
    "default_langchain_adapter",
    # LangGraph
    "LangGraphAdapter",
    "AgentSentinelNodeInterceptor",
    "default_langgraph_adapter",
    # AutoGen
    "AutoGenAdapter",
    "AgentSentinelAutoGenInterceptor",
    "default_autogen_adapter",
    # CrewAI
    "CrewAIAdapter",
    "AgentSentinelCrewAIInterceptor",
    "default_crewai_adapter",
    # Semantic Kernel
    "SemanticKernelAdapter",
    "AgentSentinelKernelFilter",
    "default_semantic_kernel_adapter",
]
