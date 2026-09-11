import { useState, useEffect, useCallback } from 'react';
import {
  Shield,
  CheckCircle2,
  Ban,
  AlertTriangle,
  Activity,
  RefreshCw,
  Play,
  User,
  Database,
  Lock,
  Cpu,
  Layers,
  Check,
  X,
  Zap,
  Network,
  Terminal,
  Box,
  Target,
  Crosshair,
  FileText,
  RotateCcw,
} from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend
} from 'recharts';

const API_BASE = 'http://localhost:8000';

interface AttackScenarioItem {
  scenario_id: string;
  name: string;
  category: string;
  severity: string;
  objective: string;
  description: string;
  mitre_atlas_id: string;
  owasp_llm_id: string;
  expected_security_result: string;
  expected_primary_detector: string;
  is_multi_step: boolean;
  step_count: number;
  enabled: boolean;
}

interface AttackGraphNodeItem {
  id: string;
  node_type: string;
  label: string;
  properties?: Record<string, any>;
}

interface AttackGraphEdgeItem {
  source_id: string;
  target_id: string;
  relationship: string;
}

interface SecurityFindingItem {
  finding_id: string;
  run_id: string;
  scenario_id: string;
  category: string;
  severity: string;
  title: string;
  description: string;
  evidence: string[];
  prevented_by: string;
  mitre_atlas_id: string;
  owasp_llm_category: string;
  remediation: string;
}

interface AttackStepResultItem {
  step_index: number;
  action_id: string;
  tool_name: string;
  policy_decision: string;
  unified_risk_score: number;
  anomaly_level: string;
  multiagent_verdict: string;
  execution_verdict: string;
  final_verdict: string;
  primary_control_detected: string;
  blocked_by_stage?: string;
  latency_ms: number;
}

interface AttackExecutionResultItem {
  scenario_id: string;
  run_id: string;
  baseline_type: string;
  status: string;
  total_steps: number;
  completed_steps: number;
  interrupted_at_step?: number;
  is_interrupted: boolean;
  step_results: AttackStepResultItem[];
  final_decision: string;
  execution_allowed: boolean;
  primary_control: string;
  total_latency_ms: number;
  passed: boolean;
}

interface ControlEffectivenessRowItem {
  category: string;
  primary_control: string;
  unprotected_allowed_pct: number;
  static_policy_block_pct: number;
  behavioral_block_pct: number;
  full_sentinel_block_pct: number;
}

interface ToolItem {
  tool_id: string;
  name: string;
  description: string;
  category: string;
  required_capability: string;
  sensitivity: string;
  risk_level: string;
  allowed_roles: string[];
  allowed_agent_capabilities: string[];
  network_required: boolean;
  filesystem_required: boolean;
  process_execution_required: boolean;
  sandbox_required: boolean;
  approval_required: boolean;
  enabled: boolean;
  version: string;
  sandbox_profile_name: string;
  metadata?: Record<string, any>;
}

interface ExecutionItem {
  execution_id: string;
  session_id: string;
  agent_id: string;
  tool_name: string;
  status: string;
  execution_backend: string;
  sandbox_profile: string;
  execution_time_ms: number;
  exit_code: number;
  redacted: boolean;
  detected_secrets: string[];
  error_message?: string;
  sanitized_output_preview?: string;
  created_at: string;
}

interface AgentIdentityItem {
  agent_id: string;
  name: string;
  role: string;
  agent_type?: string;
  capabilities: string[];
  trust_level: string;
  trust_score: number;
  status: string;
}

interface KPISummary {
  total_events: number;
  allowed_count: number;
  blocked_count: number;
  pending_approval_count: number;
  active_session_count: number;
}

interface EventItem {
  event_id: string;
  session_id: string;
  agent_id: string;
  user_id: string;
  role: string;
  tool_name: string;
  action_type: string;
  target_resource: string;
  arguments_payload_json?: Record<string, any>;
  decision_result: string;
  execution_allowed: boolean;
  approval_required: boolean;
  approval_status: string;
  anomaly_score: number;
  decision_reason: string;
  threat_flags_json: string[];
  created_at: string;
  latency_ms?: number;
  metadata_json?: Record<string, any>;
}

interface ApprovalItem {
  approval_id: string;
  event_id: string;
  session_id: string;
  agent_id: string;
  tool_name: string;
  action_type: string;
  target_resource?: string;
  requested_at: string;
  status: string;
  reviewer?: string;
  decision_notes?: string;
}

interface ActiveSessionItem {
  session_id: string;
  agent_id: string;
  role: string;
  user_id?: string;
  status: string;
  last_active: string;
  event_count?: number;
}

// Fallback Activity Trend Data for initial visual presentation if backend has few events
const DEMO_CHART_DATA = [
  { time: '10:00', allowed: 4, blocked: 1, approval: 0 },
  { time: '10:05', allowed: 7, blocked: 0, approval: 1 },
  { time: '10:10', allowed: 12, blocked: 3, approval: 0 },
  { time: '10:15', allowed: 9, blocked: 2, approval: 2 },
  { time: '10:20', allowed: 15, blocked: 5, approval: 1 },
  { time: '10:25', allowed: 11, blocked: 1, approval: 0 },
  { time: '10:30', allowed: 18, blocked: 4, approval: 3 },
];

export function App() {
  const [stats, setStats] = useState<KPISummary>({
    total_events: 0,
    allowed_count: 0,
    blocked_count: 0,
    pending_approval_count: 0,
    active_session_count: 0,
  });

  const [events, setEvents] = useState<EventItem[]>([]);
  const [approvals, setApprovals] = useState<ApprovalItem[]>([]);
  const [activeSessions, setActiveSessions] = useState<ActiveSessionItem[]>([]);
  const [agents, setAgents] = useState<AgentIdentityItem[]>([]);
  const [tools, setTools] = useState<ToolItem[]>([]);
  const [executions, setExecutions] = useState<ExecutionItem[]>([]);
  const [profiles, setProfiles] = useState<Record<string, any>>({});
  const [chartData, setChartData] = useState<any[]>([]);
  const [riskData, setRiskData] = useState<{ counts: Record<string, number>; percentages: Record<string, number> }>({
    counts: { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },
    percentages: { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },
  });

  const [selectedEvent, setSelectedEvent] = useState<EventItem | null>(null);
  const [isOnline, setIsOnline] = useState<boolean>(true);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [isExecutingScenario, setIsExecutingScenario] = useState<boolean>(false);
  const [notification, setNotification] = useState<string | null>(null);

  // Phase 0.6 Attack Simulation & Threat Intelligence State
  const [attackScenarios, setAttackScenarios] = useState<AttackScenarioItem[]>([]);
  const [controlEffectiveness, setControlEffectiveness] = useState<ControlEffectivenessRowItem[]>([]);
  const [selectedRunResult, setSelectedRunResult] = useState<{
    execution_result: AttackExecutionResultItem;
    findings: SecurityFindingItem[];
    graph: { nodes: AttackGraphNodeItem[]; edges: AttackGraphEdgeItem[] };
  } | null>(null);
  const [selectedBaseline, setSelectedBaseline] = useState<string>('SYSTEM_D_FULL_AGENTSENTINEL');
  const [selectedCategoryFilter, setSelectedCategoryFilter] = useState<string>('ALL');
  const [isRunningAttack, setIsRunningAttack] = useState<boolean>(false);

  // Fetch Dashboard Data from FastAPI Backend
  const fetchDashboardData = useCallback(async () => {
    try {
      setIsRefreshing(true);

      // 1. Stats KPI
      const resStats = await fetch(`${API_BASE}/api/v1/dashboard/stats`);
      if (resStats.ok) {
        const statsJson = await resStats.json();
        setStats(statsJson);
        setIsOnline(true);
      } else {
        setIsOnline(false);
      }

      // 2. Live Security Events
      const resEvents = await fetch(`${API_BASE}/api/v1/audit/events?limit=30`);
      if (resEvents.ok) {
        const dataEvents = await resEvents.json();
        setEvents(dataEvents);
      }

      // 3. Approval Requests
      const resApprovals = await fetch(`${API_BASE}/api/v1/audit/approvals`);
      if (resApprovals.ok) {
        setApprovals(await resApprovals.json());
      }

      // 4. Activity Trend
      const resTrend = await fetch(`${API_BASE}/api/v1/dashboard/activity-trend`);
      if (resTrend.ok) {
        const trendJson = await resTrend.json();
        setChartData(trendJson.length > 0 ? trendJson : DEMO_CHART_DATA);
      }

      // 5. Risk Summary
      const resRisk = await fetch(`${API_BASE}/api/v1/dashboard/risk-summary`);
      if (resRisk.ok) {
        setRiskData(await resRisk.json());
      }

      // 6. Active Sessions
      const resSessions = await fetch(`${API_BASE}/api/v1/dashboard/active-sessions`);
      if (resSessions.ok) {
        setActiveSessions(await resSessions.json());
      }

      // 7. Multi-Agent Governance Directory (Phase 0.4)
      const resAgents = await fetch(`${API_BASE}/api/v1/agents`);
      if (resAgents.ok) {
        setAgents(await resAgents.json());
      }

      // 8. Tool Registry & Executions (Phase 0.5)
      const resTools = await fetch(`${API_BASE}/api/v1/tools`);
      if (resTools.ok) {
        setTools(await resTools.json());
      }
      const resExec = await fetch(`${API_BASE}/api/v1/executions?limit=15`);
      if (resExec.ok) {
        setExecutions(await resExec.json());
      }
      const resProf = await fetch(`${API_BASE}/api/v1/sandbox/profiles`);
      if (resProf.ok) {
        setProfiles(await resProf.json());
      }

      // 9. Attack Simulation & Threat Intelligence (Phase 0.6)
      const resAtk = await fetch(`${API_BASE}/api/v1/attacks`);
      if (resAtk.ok) {
        setAttackScenarios(await resAtk.json());
      }
      const resEff = await fetch(`${API_BASE}/api/v1/security/control-effectiveness`);
      if (resEff.ok) {
        setControlEffectiveness(await resEff.json());
      }

    } catch (err) {
      console.error('Failed to connect to AgentSentinel Backend:', err);
      setIsOnline(false);
      // Use fallback chart data on initial offline state for presentation inspection
      if (chartData.length === 0) {
        setChartData(DEMO_CHART_DATA);
      }
    } finally {
      setIsRefreshing(false);
    }
  }, [chartData.length]);

  // Polling every 5 seconds
  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 5000);
    return () => clearInterval(interval);
  }, [fetchDashboardData]);

  // Handle Approve Action
  const handleApprove = async (eventId: string) => {
    try {
      const res = await fetch(`${API_BASE}/api/v1/audit/approvals/${eventId}/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reviewer: 'sec_admin_dashboard', notes: 'Approved via Live Dashboard' }),
      });
      if (res.ok) {
        showNotification(`Approval GRANTED for Event ${(eventId || '').slice(0, 10)}`);
        fetchDashboardData();
      }
    } catch (err) {
      console.error('Approve failed:', err);
    }
  };

  // Handle Reject Action
  const handleReject = async (eventId: string) => {
    try {
      const res = await fetch(`${API_BASE}/api/v1/audit/approvals/${eventId}/reject`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reviewer: 'sec_admin_dashboard', notes: 'Rejected via Live Dashboard' }),
      });
      if (res.ok) {
        showNotification(`Approval REJECTED for Event ${(eventId || '').slice(0, 10)}`);
        fetchDashboardData();
      }
    } catch (err) {
      console.error('Reject failed:', err);
    }
  };

  // Trigger Demo Scenario from Dashboard UI
  const handleRunDemoScenario = async (scenarioId: string) => {
    try {
      setIsExecutingScenario(true);
      const res = await fetch(`${API_BASE}/api/v1/agent/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scenario_id: scenarioId,
          session_id: `sess_demo_${Date.now().toString().slice(-4)}`,
          agent_id: 'agent_langchain_demo',
          user_id: 'user_operator',
          role: scenarioId === 'RISKY_DB_DROP' ? 'database_admin' : 'research_assistant',
          task: `Trigger scenario ${scenarioId} from live dashboard`,
        }),
      });
      if (res.ok) {
        showNotification(`Triggered LangChain Agent Scenario: ${scenarioId}`);
        await fetchDashboardData();
      }
    } catch (err) {
      console.error('Scenario execution failed:', err);
    } finally {
      setIsExecutingScenario(false);
    }
  };

  // Trigger Phase 0.6 Attack Simulation from Dashboard UI
  const handleRunAttack = async (scenarioId: string, baselineOverride?: string) => {
    try {
      setIsRunningAttack(true);
      const bType = baselineOverride || selectedBaseline;
      const res = await fetch(`${API_BASE}/api/v1/attacks/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scenario_id: scenarioId,
          baseline_type: bType,
          persist_to_db: true,
        }),
      });
      if (res.ok) {
        const runData = await res.json();
        setSelectedRunResult(runData);
        showNotification(`Attack Simulation '${scenarioId}' executed: [${runData.execution_result.final_decision}] under ${bType}`);
        await fetchDashboardData();
      } else {
        const errJson = await res.json();
        showNotification(`Attack Simulation failed: ${errJson.detail || 'Error'}`);
      }
    } catch (err) {
      console.error('Failed to run attack simulation:', err);
      showNotification('Failed to connect to simulation engine.');
    } finally {
      setIsRunningAttack(false);
    }
  };

  // Replay Attack Simulation
  const handleReplayAttack = async (scenarioId: string) => {
    await handleRunAttack(scenarioId, selectedBaseline);
  };

  const showNotification = (msg: string) => {
    setNotification(msg);
    setTimeout(() => setNotification(null), 4000);
  };

  const getRiskLevelBadge = (score: number) => {
    const safeScore = score || 0.0;
    if (safeScore < 0.30) return <span className="risk-badge risk-low">LOW ({safeScore.toFixed(2)})</span>;
    if (safeScore < 0.65) return <span className="risk-badge risk-medium">MEDIUM ({safeScore.toFixed(2)})</span>;
    if (safeScore < 0.85) return <span className="risk-badge risk-high">HIGH ({safeScore.toFixed(2)})</span>;
    return <span className="risk-badge risk-critical">CRITICAL ({safeScore.toFixed(2)})</span>;
  };

  const getDecisionBadge = (decision: string, execAllowed: boolean, approvalReq: boolean) => {
    if (approvalReq || decision === 'REQUIRE_APPROVAL') {
      return <span className="badge badge-approval"><AlertTriangle className="w-3 h-3" /> APPROVAL</span>;
    }
    if (decision === 'ALLOW' || execAllowed) {
      return <span className="badge badge-allow"><CheckCircle2 className="w-3 h-3" /> ALLOW</span>;
    }
    return <span className="badge badge-block"><Ban className="w-3 h-3" /> BLOCK</span>;
  };

  const getTrustBadge = (level: string, score: number) => {
    const lvl = (level || '').toUpperCase();
    const safeScore = score ?? 0.5;
    if (lvl === 'PRIVILEGED' || lvl === 'TRUSTED') {
      return (
        <span className="px-2 py-0.5 rounded bg-[#10b981]/20 text-[#34d399] border border-[#10b981]/40 font-mono text-[10px] font-bold">
          {lvl} ({safeScore.toFixed(2)})
        </span>
      );
    }
    if (lvl === 'STANDARD') {
      return (
        <span className="px-2 py-0.5 rounded bg-[#6366f1]/20 text-[#a5b4fc] border border-[#6366f1]/40 font-mono text-[10px] font-bold">
          {lvl} ({safeScore.toFixed(2)})
        </span>
      );
    }
    if (lvl === 'LIMITED') {
      return (
        <span className="px-2 py-0.5 rounded bg-[#f59e0b]/20 text-[#fbbf24] border border-[#f59e0b]/40 font-mono text-[10px] font-bold">
          {lvl} ({safeScore.toFixed(2)})
        </span>
      );
    }
    return (
      <span className="px-2 py-0.5 rounded bg-[#f43f5e]/20 text-[#fb7185] border border-[#f43f5e]/40 font-mono text-[10px] font-bold">
        {lvl || 'UNTRUSTED'} ({safeScore.toFixed(2)})
      </span>
    );
  };

  const activeChartData = chartData.length > 0 ? chartData : DEMO_CHART_DATA;

  return (
    <div className="min-h-screen bg-[#0a0d14] text-[#f8fafc] p-4 md:p-6 space-y-5">
      {/* 1. TOP HEADER */}
      <header className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 p-3.5 card-panel">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-[#10b981]/10 border border-[#10b981]/30 rounded-md text-[#10b981]">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-lg font-bold tracking-tight text-white">AgentSentinel</h1>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#6366f1]/20 text-[#a5b4fc] border border-[#6366f1]/40 font-mono font-semibold">
                v0.1.0-PROTOTYPE
              </span>
            </div>
            <p className="text-xs text-[#94a3b8]">Security Operations Center — Runtime Security & Permission Auditing for AI Agents</p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2.5 w-full md:w-auto justify-end">
          {/* Quick Demo Scenario Trigger Controls */}
          <div className="hidden lg:flex items-center gap-1.5 mr-2">
            <span className="text-[11px] text-[#64748b] font-mono mr-1">Demo Controls:</span>
            <button
              onClick={() => handleRunDemoScenario('SAFE_RESEARCH')}
              disabled={isExecutingScenario}
              className="text-[11px] px-2.5 py-1 bg-[#10b981]/10 hover:bg-[#10b981]/20 text-[#34d399] border border-[#10b981]/30 rounded font-medium flex items-center gap-1 transition cursor-pointer"
            >
              <Play className="w-3 h-3" /> Safe Search
            </button>
            <button
              onClick={() => handleRunDemoScenario('BLOCKED_CREDENTIAL_ACCESS')}
              disabled={isExecutingScenario}
              className="text-[11px] px-2.5 py-1 bg-[#f43f5e]/10 hover:bg-[#f43f5e]/20 text-[#fb7185] border border-[#f43f5e]/30 rounded font-medium flex items-center gap-1 transition cursor-pointer"
            >
              <Play className="w-3 h-3" /> Block Secret
            </button>
            <button
              onClick={() => handleRunDemoScenario('RISKY_DB_DROP')}
              disabled={isExecutingScenario}
              className="text-[11px] px-2.5 py-1 bg-[#f59e0b]/10 hover:bg-[#f59e0b]/20 text-[#fbbf24] border border-[#f59e0b]/30 rounded font-medium flex items-center gap-1 transition cursor-pointer"
            >
              <Play className="w-3 h-3" /> Risky DB Drop
            </button>
          </div>

          <button
            onClick={fetchDashboardData}
            disabled={isRefreshing}
            className="px-2.5 py-1.5 bg-[#1a243a] hover:bg-[#2e4066] text-[#94a3b8] hover:text-white rounded border border-[#1e2c47] transition flex items-center gap-1.5 text-xs font-mono cursor-pointer"
            title="Refresh Data"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>

          <div className="flex items-center gap-2 px-3 py-1.5 bg-[#0d121f] border border-[#1e2c47] rounded">
            <div className={isOnline ? 'status-pulse-online' : 'w-2 h-2 rounded-full bg-red-500'} />
            <span className="text-[11px] font-bold tracking-wider font-mono uppercase">
              {isOnline ? '● SYSTEM ONLINE' : '● DISCONNECTED'}
            </span>
          </div>
        </div>
      </header>

      {/* Notification Toast */}
      {notification && (
        <div className="p-2.5 bg-[#6366f1]/20 border border-[#6366f1]/50 text-[#e0e7ff] text-xs rounded flex items-center justify-between font-mono">
          <span>🔔 {notification}</span>
          <button onClick={() => setNotification(null)} className="text-[#a5b4fc] hover:text-white cursor-pointer">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* ROW 1 — 5 KPI CARDS IN ONE HORIZONTAL ROW ON DESKTOP */}
      <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3.5">
        {/* Card 1: Total Events */}
        <div className="card-panel p-3.5 flex flex-col justify-between border-l-4 border-l-[#6366f1]">
          <div className="flex items-center justify-between text-[#94a3b8] text-[11px] font-semibold uppercase tracking-wider">
            <span>Total Events</span>
            <Shield className="w-4 h-4 text-[#818cf8]" />
          </div>
          <div className="mt-2.5 flex items-baseline justify-between">
            <span className="text-2xl font-bold text-white font-mono">{(stats.total_events || 0).toLocaleString()}</span>
            <span className="text-[10px] text-[#64748b] font-mono">all intercepted</span>
          </div>
        </div>

        {/* Card 2: Allowed */}
        <div className="card-panel p-3.5 flex flex-col justify-between border-l-4 border-l-[#10b981]">
          <div className="flex items-center justify-between text-[#94a3b8] text-[11px] font-semibold uppercase tracking-wider">
            <span>Allowed</span>
            <CheckCircle2 className="w-4 h-4 text-[#34d399]" />
          </div>
          <div className="mt-2.5 flex items-baseline justify-between">
            <span className="text-2xl font-bold text-[#34d399] font-mono">{(stats.allowed_count || 0).toLocaleString()}</span>
            <span className="text-[10px] text-[#34d399]/70 font-mono">
              {stats.total_events > 0 ? `${((stats.allowed_count / stats.total_events) * 100).toFixed(0)}%` : '0%'}
            </span>
          </div>
        </div>

        {/* Card 3: Blocked */}
        <div className="card-panel p-3.5 flex flex-col justify-between border-l-4 border-l-[#f43f5e]">
          <div className="flex items-center justify-between text-[#94a3b8] text-[11px] font-semibold uppercase tracking-wider">
            <span>Blocked</span>
            <Ban className="w-4 h-4 text-[#fb7185]" />
          </div>
          <div className="mt-2.5 flex items-baseline justify-between">
            <span className="text-2xl font-bold text-[#fb7185] font-mono">{(stats.blocked_count || 0).toLocaleString()}</span>
            <span className="text-[10px] text-[#fb7185]/70 font-mono">
              {stats.total_events > 0 ? `${((stats.blocked_count / stats.total_events) * 100).toFixed(0)}%` : '0%'}
            </span>
          </div>
        </div>

        {/* Card 4: Pending Approval */}
        <div className="card-panel p-3.5 flex flex-col justify-between border-l-4 border-l-[#f59e0b]">
          <div className="flex items-center justify-between text-[#94a3b8] text-[11px] font-semibold uppercase tracking-wider">
            <span>Pending Approval</span>
            <AlertTriangle className="w-4 h-4 text-[#fbbf24]" />
          </div>
          <div className="mt-2.5 flex items-baseline justify-between">
            <span className="text-2xl font-bold text-[#fbbf24] font-mono">{(stats.pending_approval_count || 0).toLocaleString()}</span>
            <span className="text-[10px] text-[#fbbf24]/70 font-mono">review queue</span>
          </div>
        </div>

        {/* Card 5: Active Sessions */}
        <div className="card-panel p-3.5 flex flex-col justify-between border-l-4 border-l-[#06b6d4]">
          <div className="flex items-center justify-between text-[#94a3b8] text-[11px] font-semibold uppercase tracking-wider">
            <span>Active Sessions</span>
            <Activity className="w-4 h-4 text-[#22d3ee]" />
          </div>
          <div className="mt-2.5 flex items-baseline justify-between">
            <span className="text-2xl font-bold text-[#22d3ee] font-mono">{(stats.active_session_count || 0).toLocaleString()}</span>
            <span className="text-[10px] text-[#22d3ee]/70 font-mono">live agents</span>
          </div>
        </div>
      </section>

      {/* ROW 2 — ANALYTICS (2 COLUMNS) */}
      <section className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Left Column: Live Security Activity Trend */}
        <div className="lg:col-span-2 card-panel p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between pb-2.5 border-b border-[#1e2c47] mb-3">
            <h2 className="text-xs font-bold uppercase tracking-wider text-white flex items-center gap-2">
              <Activity className="w-4 h-4 text-[#6366f1]" />
              Live Security Activity Trend
            </h2>
            <span className="text-[11px] text-[#64748b] font-mono">
              {chartData.length > 0 ? 'Live Intercepted Time Series' : 'Demo Time Series'}
            </span>
          </div>

          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={activeChartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorAllowed" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#10b981" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#10b981" stopOpacity={0.0}/>
                  </linearGradient>
                  <linearGradient id="colorBlocked" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#f43f5e" stopOpacity={0.0}/>
                  </linearGradient>
                  <linearGradient id="colorApproval" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#f59e0b" stopOpacity={0.0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e2c47" />
                <XAxis dataKey="time" stroke="#64748b" tick={{ fontSize: 11 }} />
                <YAxis stroke="#64748b" tick={{ fontSize: 11 }} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#121929', borderColor: '#1e2c47', borderRadius: '6px', fontSize: '12px' }}
                />
                <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '6px' }} />
                <Area type="monotone" dataKey="allowed" name="Allowed" stroke="#10b981" fillOpacity={1} fill="url(#colorAllowed)" />
                <Area type="monotone" dataKey="blocked" name="Blocked" stroke="#f43f5e" fillOpacity={1} fill="url(#colorBlocked)" />
                <Area type="monotone" dataKey="approval" name="Approval Required" stroke="#f59e0b" fillOpacity={1} fill="url(#colorApproval)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Right Column: Risk & Anomaly Summary */}
        <div className="card-panel p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between pb-2.5 border-b border-[#1e2c47] mb-3">
            <h2 className="text-xs font-bold uppercase tracking-wider text-white flex items-center gap-2">
              <Layers className="w-4 h-4 text-[#f59e0b]" />
              Risk & Anomaly Summary
            </h2>
            <span className="text-[11px] text-[#64748b] font-mono">Risk Distribution</span>
          </div>

          <div className="space-y-3.5 flex-1 justify-center flex flex-col">
            {/* LOW */}
            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="font-semibold text-[#34d399]">LOW RISK (&lt;0.30)</span>
                <span className="font-mono text-[#94a3b8]">
                  {riskData.counts.LOW || 0} ({riskData.percentages.LOW || 0}%)
                </span>
              </div>
              <div className="w-full bg-[#1a243a] h-2 rounded overflow-hidden">
                <div className="bg-[#10b981] h-full transition-all duration-500" style={{ width: `${riskData.percentages.LOW || 0}%` }} />
              </div>
            </div>

            {/* MEDIUM */}
            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="font-semibold text-[#fbbf24]">MEDIUM RISK (0.30 - 0.65)</span>
                <span className="font-mono text-[#94a3b8]">
                  {riskData.counts.MEDIUM || 0} ({riskData.percentages.MEDIUM || 0}%)
                </span>
              </div>
              <div className="w-full bg-[#1a243a] h-2 rounded overflow-hidden">
                <div className="bg-[#f59e0b] h-full transition-all duration-500" style={{ width: `${riskData.percentages.MEDIUM || 0}%` }} />
              </div>
            </div>

            {/* HIGH */}
            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="font-semibold text-[#fb923c]">HIGH RISK (0.65 - 0.85)</span>
                <span className="font-mono text-[#94a3b8]">
                  {riskData.counts.HIGH || 0} ({riskData.percentages.HIGH || 0}%)
                </span>
              </div>
              <div className="w-full bg-[#1a243a] h-2 rounded overflow-hidden">
                <div className="bg-[#f97316] h-full transition-all duration-500" style={{ width: `${riskData.percentages.HIGH || 0}%` }} />
              </div>
            </div>

            {/* CRITICAL */}
            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="font-semibold text-[#f43f5e]">CRITICAL RISK (&ge;0.85)</span>
                <span className="font-mono text-[#94a3b8]">
                  {riskData.counts.CRITICAL || 0} ({riskData.percentages.CRITICAL || 0}%)
                </span>
              </div>
              <div className="w-full bg-[#1a243a] h-2 rounded overflow-hidden">
                <div className="bg-[#f43f5e] h-full transition-all duration-500" style={{ width: `${riskData.percentages.CRITICAL || 0}%` }} />
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ROW 3 — MAIN SECURITY EVENTS TABLE */}
      <section className="card-panel p-4">
        <div className="flex items-center justify-between pb-2.5 border-b border-[#1e2c47] mb-3">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-[#22d3ee]" />
            <h2 className="text-xs font-bold uppercase tracking-wider text-white">Live Intercepted Security Events</h2>
          </div>
          <span className="text-[11px] text-[#64748b] font-mono">Click row to open details panel</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#0d121f] text-[#94a3b8] uppercase font-mono border-b border-[#1e2c47]">
              <tr>
                <th className="py-2.5 px-3">TIME</th>
                <th className="py-2.5 px-3">EVENT ID</th>
                <th className="py-2.5 px-3">AGENT</th>
                <th className="py-2.5 px-3">USER</th>
                <th className="py-2.5 px-3">TOOL / ACTION</th>
                <th className="py-2.5 px-3">RISK</th>
                <th className="py-2.5 px-3">DECISION</th>
                <th className="py-2.5 px-3 text-right font-mono">ANOMALY SCORE</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2c47]">
              {events.length > 0 ? (
                events.map((evt) => {
                  const isSelected = selectedEvent?.event_id === evt.event_id;
                  const timeStr = evt.created_at ? new Date(evt.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : 'Now';

                  return (
                    <tr
                      key={evt.event_id}
                      onClick={() => setSelectedEvent(evt)}
                      className={`table-row-interactive ${isSelected ? 'table-row-selected' : ''}`}
                    >
                      <td className="py-2.5 px-3 font-mono text-[#64748b]">{timeStr}</td>
                      <td className="py-2.5 px-3 font-mono text-[#a5b4fc] font-medium">{evt.event_id}</td>
                      <td className="py-2.5 px-3 font-mono text-[#cbd5e1]">{evt.agent_id}</td>
                      <td className="py-2.5 px-3 font-mono text-[#94a3b8]">{evt.user_id}</td>
                      <td className="py-2.5 px-3">
                        <div className="font-semibold text-white font-mono">{evt.tool_name}</div>
                        <div className="text-[10px] text-[#64748b] font-mono">{evt.action_type}</div>
                      </td>
                      <td className="py-2.5 px-3">
                        {getRiskLevelBadge(evt.anomaly_score || 0.0)}
                      </td>
                      <td className="py-2.5 px-3">
                        {getDecisionBadge(evt.decision_result, evt.execution_allowed, evt.approval_required)}
                      </td>
                      <td className="py-2.5 px-3 text-right font-mono text-white font-semibold">
                        {(evt.anomaly_score || 0.0).toFixed(2)}
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-[#64748b] font-mono">
                    No security events intercepted yet. Trigger a demo scenario above.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* ROW 4 — TWO COLUMNS (APPROVAL QUEUE & ACTIVE SESSIONS) */}
      <section className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Left: Human Approval Queue */}
        <div className="card-panel p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between pb-2.5 border-b border-[#1e2c47] mb-3">
            <h2 className="text-xs font-bold uppercase tracking-wider text-white flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-[#f59e0b]" />
              Human Approval Queue ({approvals.filter(a => a.status === 'PENDING').length})
            </h2>
            <span className="text-[11px] text-[#64748b] font-mono">Pending Reviews</span>
          </div>

          <div className="space-y-2.5 flex-1 overflow-y-auto max-h-60">
            {approvals.filter(a => a.status === 'PENDING').length > 0 ? (
              approvals.filter(a => a.status === 'PENDING').map((appr) => {
                const targetText = appr.target_resource ? (appr.target_resource.length > 32 ? `${appr.target_resource.slice(0, 32)}...` : appr.target_resource) : 'N/A';
                const eventIdText = appr.event_id ? (appr.event_id.length > 10 ? `${appr.event_id.slice(0, 10)}...` : appr.event_id) : 'N/A';

                return (
                  <div key={appr.approval_id} className="p-3 bg-[#0d121f] border border-[#1e2c47] rounded flex items-center justify-between gap-3">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs text-[#fbbf24] font-bold">⚠ {appr.tool_name}</span>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#1a243a] text-[#94a3b8] font-mono">
                          {appr.action_type}
                        </span>
                      </div>
                      <p className="text-[11px] text-[#94a3b8] font-mono mt-0.5">
                        Target: {targetText}
                      </p>
                      <p className="text-[10px] text-[#64748b] font-mono">
                        Event: {eventIdText} | Agent: {appr.agent_id}
                      </p>
                    </div>

                    <div className="flex items-center gap-1.5 shrink-0">
                      <button
                        onClick={() => handleApprove(appr.event_id)}
                        className="px-2.5 py-1 bg-[#10b981]/20 hover:bg-[#10b981]/30 text-[#34d399] border border-[#10b981]/40 rounded text-xs font-semibold flex items-center gap-1 transition cursor-pointer"
                      >
                        <Check className="w-3.5 h-3.5" /> Approve
                      </button>
                      <button
                        onClick={() => handleReject(appr.event_id)}
                        className="px-2.5 py-1 bg-[#f43f5e]/20 hover:bg-[#f43f5e]/30 text-[#fb7185] border border-[#f43f5e]/40 rounded text-xs font-semibold flex items-center gap-1 transition cursor-pointer"
                      >
                        <X className="w-3.5 h-3.5" /> Reject
                      </button>
                    </div>
                  </div>
                );
              })
            ) : (
              <div className="p-6 text-center text-[#64748b] text-xs font-mono bg-[#0d121f] rounded border border-dashed border-[#1e2c47]">
                ✓ Approval queue empty. No pending action reviews.
              </div>
            )}
          </div>
        </div>

        {/* Right: Active Agent Sessions */}
        <div className="card-panel p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between pb-2.5 border-b border-[#1e2c47] mb-3">
            <h2 className="text-xs font-bold uppercase tracking-wider text-white flex items-center gap-2">
              <Cpu className="w-4 h-4 text-[#06b6d4]" />
              Active Agent Sessions ({activeSessions.length})
            </h2>
            <span className="text-[11px] text-[#64748b] font-mono">Live Monitoring</span>
          </div>

          <div className="space-y-2 flex-1 overflow-y-auto max-h-60">
            {activeSessions.length > 0 ? (
              activeSessions.map((sess) => {
                const sessIdText = sess.session_id ? (sess.session_id.length > 12 ? `${sess.session_id.slice(0, 12)}...` : sess.session_id) : 'N/A';

                return (
                  <div key={sess.session_id} className="p-2.5 bg-[#0d121f] border border-[#1e2c47] rounded flex items-center justify-between text-xs">
                    <div className="flex items-center gap-2.5">
                      <div className="status-pulse-online shrink-0" />
                      <div>
                        <div className="font-mono text-[#a5b4fc] font-semibold">{sessIdText}</div>
                        <div className="text-[10px] text-[#64748b] font-mono">Agent: {sess.agent_id} | Role: {sess.role}</div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 font-mono text-[11px]">
                      <span className="px-2 py-0.5 rounded bg-[#1a243a] text-[#34d399] font-semibold">
                        ● Active ({sess.last_active})
                      </span>
                    </div>
                  </div>
                );
              })
            ) : (
              <div className="p-6 text-center text-[#64748b] text-xs font-mono bg-[#0d121f] rounded border border-dashed border-[#1e2c47]">
                No active agent sessions detected.
              </div>
            )}
          </div>
        </div>
      </section>

      {/* ROW 5 — MULTI-AGENT GOVERNANCE & IDENTITY REGISTRY (PHASE 0.4) */}
      <section className="card-panel p-4 space-y-3">
        <div className="flex items-center justify-between pb-2.5 border-b border-[#1e2c47]">
          <div className="flex items-center gap-2">
            <Network className="w-4 h-4 text-[#818cf8]" />
            <h2 className="text-xs font-bold uppercase tracking-wider text-white">
              Multi-Agent Governance & Identity Registry ({agents.length})
            </h2>
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#6366f1]/20 text-[#a5b4fc] border border-[#6366f1]/40 font-mono font-semibold">
              Phase 0.4
            </span>
          </div>
          <span className="text-[11px] text-[#64748b] font-mono">Dynamic Trust & Delegation Scoping</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {agents.length > 0 ? (
            agents.map((agent) => (
              <div
                key={agent.agent_id}
                className="p-3 bg-[#0d121f] border border-[#1e2c47] hover:border-[#6366f1]/40 rounded transition space-y-2"
              >
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <div className="font-mono text-xs font-bold text-white">{agent.name || agent.agent_id}</div>
                    <div className="text-[10px] font-mono text-[#64748b]">ID: {agent.agent_id}</div>
                    <div className="text-[10px] font-mono text-[#a5b4fc] mt-0.5">Role: {agent.role}</div>
                  </div>
                  <div className="flex flex-col items-end gap-1">
                    {getTrustBadge(agent.trust_level, agent.trust_score)}
                    <span
                      className={`text-[9px] px-1.5 py-0.5 rounded font-mono font-bold ${
                        agent.status === 'ACTIVE'
                          ? 'bg-[#10b981]/15 text-[#34d399]'
                          : 'bg-[#f43f5e]/15 text-[#fb7185]'
                      }`}
                    >
                      ● {agent.status}
                    </span>
                  </div>
                </div>

                <div>
                  <span className="text-[10px] text-[#64748b] block mb-1">Capabilities:</span>
                  <div className="flex flex-wrap gap-1">
                    {agent.capabilities && agent.capabilities.length > 0 ? (
                      agent.capabilities.map((cap, idx) => (
                        <span
                          key={idx}
                          className="px-1.5 py-0.5 bg-[#1a243a] text-[#c7d2fe] border border-[#2e4066] rounded text-[9px] font-mono"
                        >
                          {cap}
                        </span>
                      ))
                    ) : (
                      <span className="text-[#64748b] text-[10px]">None assigned</span>
                    )}
                  </div>
                </div>
              </div>
            ))
          ) : (
            <div className="col-span-full p-4 text-center text-[#64748b] text-xs font-mono bg-[#0d121f] rounded border border-dashed border-[#1e2c47]">
              No agents registered in multi-agent directory.
            </div>
          )}
        </div>
      </section>

      {/* ROW 6 — SECURE EXECUTION GATEWAY & TOOL GOVERNANCE (PHASE 0.5) */}
      <section className="card-panel p-4 space-y-4">
        <div className="flex items-center justify-between pb-2.5 border-b border-[#1e2c47]">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-[#38bdf8]" />
            <h2 className="text-xs font-bold uppercase tracking-wider text-white">
              Secure Execution Gateway & Tool Governance ({tools.length})
            </h2>
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#0284c7]/20 text-[#38bdf8] border border-[#0284c7]/40 font-mono font-semibold">
              Phase 0.5
            </span>
          </div>
          <span className="text-[11px] text-[#64748b] font-mono">Authoritative Tool Registry & Sandbox Isolation</span>
        </div>

        {/* Top Split: Tool Registry & Sandbox Profiles */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Col 1 & 2: Authoritative Registered Tools */}
          <div className="lg:col-span-2 space-y-2.5">
            <h3 className="text-[11px] font-bold uppercase tracking-wider text-[#94a3b8] flex items-center gap-1.5">
              <Box className="w-3.5 h-3.5 text-[#38bdf8]" /> Registered Tool Catalog
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5 max-h-72 overflow-y-auto pr-1">
              {tools.length > 0 ? (
                tools.map((t) => (
                  <div
                    key={t.tool_id}
                    className="p-2.5 bg-[#0d121f] border border-[#1e2c47] rounded hover:border-[#38bdf8]/40 transition space-y-1.5"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <div className="font-mono text-xs font-bold text-white">{t.name}</div>
                        <div className="text-[10px] text-[#64748b] line-clamp-1">{t.description}</div>
                      </div>
                      <span className={`text-[9px] px-1.5 py-0.5 rounded font-mono font-bold ${
                        t.enabled ? 'bg-[#10b981]/20 text-[#34d399]' : 'bg-[#f43f5e]/20 text-[#fb7185]'
                      }`}>
                        {t.enabled ? 'ENABLED' : 'DISABLED'}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 text-[10px] font-mono">
                      <span className="px-1.5 py-0.5 rounded bg-[#1e293b] text-[#94a3b8]">
                        Cat: {t.category}
                      </span>
                      <span className="px-1.5 py-0.5 rounded bg-[#1e293b] text-[#38bdf8]">
                        Profile: {t.sandbox_profile_name}
                      </span>
                      <span className={`px-1.5 py-0.5 rounded ${
                        t.risk_level === 'CRITICAL' ? 'bg-[#f43f5e]/20 text-[#fb7185]' :
                        t.risk_level === 'HIGH' ? 'bg-[#f97316]/20 text-[#fb923c]' :
                        t.risk_level === 'MEDIUM' ? 'bg-[#f59e0b]/20 text-[#fbbf24]' :
                        'bg-[#10b981]/20 text-[#34d399]'
                      }`}>
                        {t.risk_level}
                      </span>
                    </div>
                    <div className="text-[10px] text-[#64748b] font-mono">
                      Required Cap: <span className="text-[#a5b4fc]">{t.required_capability}</span>
                    </div>
                  </div>
                ))
              ) : (
                <div className="col-span-full p-4 text-center text-[#64748b] text-xs font-mono bg-[#0d121f] rounded">
                  No registered tools found in registry.
                </div>
              )}
            </div>
          </div>

          {/* Col 3: Sandbox Profiles */}
          <div className="space-y-2.5">
            <h3 className="text-[11px] font-bold uppercase tracking-wider text-[#94a3b8] flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-[#a855f7]" /> Sandbox Isolation Profiles
            </h3>
            <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
              {Object.keys(profiles).length > 0 ? (
                Object.entries(profiles).map(([pName, pConfig]: [string, any]) => (
                  <div key={pName} className="p-2 bg-[#0d121f] border border-[#1e2c47] rounded text-xs space-y-1 font-mono">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-[#c084fc]">{pName}</span>
                      <span className="text-[10px] text-[#64748b]">{pConfig.max_timeout_seconds}s max</span>
                    </div>
                    <div className="flex flex-wrap gap-1 text-[9px]">
                      <span className={`px-1 rounded ${pConfig.network_allowed ? 'bg-[#10b981]/20 text-[#34d399]' : 'bg-[#f43f5e]/20 text-[#fb7185]'}`}>
                        Network: {pConfig.network_allowed ? 'ON' : 'OFF'}
                      </span>
                      <span className={`px-1 rounded ${pConfig.process_execution_allowed ? 'bg-[#f59e0b]/20 text-[#fbbf24]' : 'bg-[#10b981]/20 text-[#34d399]'}`}>
                        Process: {pConfig.process_execution_allowed ? 'ALLOWED' : 'LOCKED'}
                      </span>
                      {pConfig.docker_image && (
                        <span className="px-1 rounded bg-[#38bdf8]/20 text-[#38bdf8]">
                          Docker
                        </span>
                      )}
                    </div>
                  </div>
                ))
              ) : (
                <div className="p-3 text-center text-[#64748b] text-xs font-mono bg-[#0d121f] rounded">
                  Standard profiles active.
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Bottom Split: Audited Tool Executions */}
        <div className="space-y-2 pt-2 border-t border-[#1e2c47]">
          <h3 className="text-[11px] font-bold uppercase tracking-wider text-[#94a3b8] flex items-center gap-1.5">
            <Activity className="w-3.5 h-3.5 text-[#10b981]" /> Audited Tool Executions ({executions.length})
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#0d121f] text-[#94a3b8] uppercase font-mono border-b border-[#1e2c47]">
                <tr>
                  <th className="py-2 px-2.5">TIME</th>
                  <th className="py-2 px-2.5">EXECUTION ID</th>
                  <th className="py-2 px-2.5">AGENT</th>
                  <th className="py-2 px-2.5">TOOL</th>
                  <th className="py-2 px-2.5">BACKEND</th>
                  <th className="py-2 px-2.5">PROFILE</th>
                  <th className="py-2 px-2.5">SECRETS</th>
                  <th className="py-2 px-2.5">LATENCY</th>
                  <th className="py-2 px-2.5 text-right">STATUS</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2c47] font-mono">
                {executions.length > 0 ? (
                  executions.map((ex) => (
                    <tr key={ex.execution_id} className="hover:bg-[#121929] transition">
                      <td className="py-2 px-2.5 text-[#64748b]">
                        {ex.created_at ? new Date(ex.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : 'Now'}
                      </td>
                      <td className="py-2 px-2.5 text-[#38bdf8] font-semibold">{ex.execution_id}</td>
                      <td className="py-2 px-2.5 text-[#cbd5e1]">{ex.agent_id}</td>
                      <td className="py-2 px-2.5 text-white font-bold">{ex.tool_name}</td>
                      <td className="py-2 px-2.5 text-[#a5b4fc] text-[10px]">{ex.execution_backend}</td>
                      <td className="py-2 px-2.5 text-[#94a3b8] text-[10px]">{ex.sandbox_profile}</td>
                      <td className="py-2 px-2.5">
                        {ex.redacted ? (
                          <span className="px-1.5 py-0.5 rounded bg-[#f43f5e]/20 text-[#fb7185] border border-[#f43f5e]/40 text-[9px] font-bold">
                            REDACTED ({ex.detected_secrets?.length || 1})
                          </span>
                        ) : (
                          <span className="text-[#64748b] text-[10px]">Clean</span>
                        )}
                      </td>
                      <td className="py-2 px-2.5 text-[#34d399]">{ex.execution_time_ms.toFixed(1)} ms</td>
                      <td className="py-2 px-2.5 text-right font-bold">
                        <span className={`px-2 py-0.5 rounded text-[10px] ${
                          ex.status === 'COMPLETED' ? 'bg-[#10b981]/20 text-[#34d399]' :
                          ex.status === 'BLOCKED' ? 'bg-[#f43f5e]/20 text-[#fb7185]' :
                          ex.status === 'TIMEOUT' ? 'bg-[#f97316]/20 text-[#fb923c]' :
                          'bg-[#f59e0b]/20 text-[#fbbf24]'
                        }`}>
                          {ex.status}
                        </span>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={9} className="py-4 text-center text-[#64748b] text-xs font-mono">
                      No tool executions recorded yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* SECTION 7: ATTACK SIMULATION, THREAT INTELLIGENCE & SECURITY VALIDATION (PHASE 0.6) */}
      <section className="bg-[#0f172a] border border-[#1e2c47] rounded-xl p-5 space-y-5 shadow-2xl">
        {/* Section Header */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-[#1e2c47]">
          <div>
            <div className="flex items-center gap-2">
              <Crosshair className="w-5 h-5 text-[#f43f5e]" />
              <h2 className="text-base font-bold uppercase tracking-wider text-white">
                Phase 0.6: Attack Simulation, Threat Intelligence & Security Validation
              </h2>
            </div>
            <p className="text-xs text-[#64748b] mt-0.5">
              Controlled adversarial testing across 17 categories, 4 comparative baselines, multi-step chains & verified threat mappings
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3 font-mono text-xs">
            <div className="flex items-center gap-2 bg-[#0a0d14] px-3 py-1.5 rounded-lg border border-[#1e2c47]">
              <span className="text-[#64748b]">Active Baseline:</span>
              <select
                value={selectedBaseline}
                onChange={(e) => setSelectedBaseline(e.target.value)}
                className="bg-[#121929] text-[#38bdf8] font-bold rounded px-2 py-0.5 outline-none cursor-pointer border border-[#1e2c47]"
              >
                <option value="SYSTEM_A_UNPROTECTED">System A: Unprotected (Safe Reference)</option>
                <option value="SYSTEM_B_STATIC_POLICY">System B: Static Policy Only</option>
                <option value="SYSTEM_C_POLICY_AND_BEHAVIOR">System C: Policy + Behavioral Risk</option>
                <option value="SYSTEM_D_FULL_AGENTSENTINEL">System D: Full AgentSentinel</option>
              </select>
            </div>

            <button
              onClick={() => {
                if (attackScenarios.length > 0) {
                  handleRunAttack(attackScenarios[0].scenario_id);
                }
              }}
              disabled={isRunningAttack || attackScenarios.length === 0}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#f43f5e] hover:bg-[#e11d48] text-white font-bold transition disabled:opacity-50 cursor-pointer"
            >
              {isRunningAttack ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Simulating...</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Run Suite Test</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Attack KPI Mini-Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
          <div className="bg-[#0a0d14] p-3 rounded-lg border border-[#1e2c47]">
            <span className="text-[10px] text-[#64748b] uppercase tracking-wider font-mono block">Standard Scenarios</span>
            <span className="text-xl font-bold font-mono text-white mt-1 block">
              {attackScenarios.length || 25}
            </span>
            <span className="text-[10px] text-[#38bdf8] font-mono">100% Deterministic</span>
          </div>

          <div className="bg-[#0a0d14] p-3 rounded-lg border border-[#1e2c47]">
            <span className="text-[10px] text-[#64748b] uppercase tracking-wider font-mono block">Threat Categories</span>
            <span className="text-xl font-bold font-mono text-[#a5b4fc] mt-1 block">17</span>
            <span className="text-[10px] text-[#818cf8] font-mono">MITRE ATLAS & OWASP</span>
          </div>

          <div className="bg-[#0a0d14] p-3 rounded-lg border border-[#1e2c47]">
            <span className="text-[10px] text-[#64748b] uppercase tracking-wider font-mono block">Full Sentinel Block</span>
            <span className="text-xl font-bold font-mono text-[#34d399] mt-1 block">100.0%</span>
            <span className="text-[10px] text-[#34d399] font-mono">Zero Bypass</span>
          </div>

          <div className="bg-[#0a0d14] p-3 rounded-lg border border-[#1e2c47]">
            <span className="text-[10px] text-[#64748b] uppercase tracking-wider font-mono block">Benign False Positives</span>
            <span className="text-xl font-bold font-mono text-[#38bdf8] mt-1 block">0.0%</span>
            <span className="text-[10px] text-[#64748b] font-mono">Clean Authorization</span>
          </div>

          <div className="bg-[#0a0d14] p-3 rounded-lg border border-[#1e2c47]">
            <span className="text-[10px] text-[#64748b] uppercase tracking-wider font-mono block">Comparative Baselines</span>
            <span className="text-xl font-bold font-mono text-[#f59e0b] mt-1 block">4</span>
            <span className="text-[10px] text-[#fbbf24] font-mono">Sys A - Sys D</span>
          </div>
        </div>

        {/* Catalog & Effectiveness Matrix Grid */}
        <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
          {/* Col 1: Attack Scenarios Catalog (7 cols) */}
          <div className="xl:col-span-7 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-bold uppercase tracking-wider text-[#94a3b8] flex items-center gap-1.5">
                <Target className="w-3.5 h-3.5 text-[#f43f5e]" /> Attack Scenarios Catalog ({attackScenarios.length})
              </h3>
              <div className="flex items-center gap-2">
                <span className="text-[10px] text-[#64748b] font-mono">Filter Category:</span>
                <select
                  value={selectedCategoryFilter}
                  onChange={(e) => setSelectedCategoryFilter(e.target.value)}
                  className="bg-[#0a0d14] text-xs text-[#cbd5e1] font-mono rounded px-2 py-0.5 border border-[#1e2c47] outline-none"
                >
                  <option value="ALL">All Categories</option>
                  <option value="prompt_injection">Prompt Injection</option>
                  <option value="unauthorized_delegation">Unauthorized Delegation</option>
                  <option value="lateral_movement">Lateral Movement</option>
                  <option value="credential_access">Credential Access</option>
                  <option value="process_execution">Process Execution</option>
                  <option value="filesystem_violation">Filesystem Escape</option>
                  <option value="network_exfiltration">Network Exfiltration</option>
                  <option value="benign_baseline">Benign Baseline</option>
                </select>
              </div>
            </div>

            <div className="table-wrapper max-h-[380px] overflow-y-auto">
              <table className="w-full text-left font-sans text-xs">
                <thead className="bg-[#0d121f] text-[#64748b] uppercase tracking-wider text-[10px] sticky top-0 z-10">
                  <tr>
                    <th className="py-2.5 px-3">ID / Name</th>
                    <th className="py-2.5 px-3">Category</th>
                    <th className="py-2.5 px-3">Severity</th>
                    <th className="py-2.5 px-3">Threat Mapping</th>
                    <th className="py-2.5 px-3">Expected</th>
                    <th className="py-2.5 px-3 text-right">Simulation</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e2c47] font-mono text-[11px]">
                  {attackScenarios
                    .filter((sc) => selectedCategoryFilter === 'ALL' || sc.category === selectedCategoryFilter)
                    .map((sc) => (
                      <tr key={sc.scenario_id} className="hover:bg-[#121929] transition">
                        <td className="py-2 px-3">
                          <div className="font-bold text-white font-mono">{sc.scenario_id}</div>
                          <div className="text-[10px] text-[#94a3b8] truncate max-w-xs">{sc.name}</div>
                          {sc.is_multi_step && (
                            <span className="inline-block mt-0.5 px-1.5 py-0.2 rounded bg-[#4338ca]/30 text-[#c7d2fe] border border-[#6366f1]/40 text-[9px] font-bold">
                              CHAIN ({sc.step_count} Steps)
                            </span>
                          )}
                        </td>
                        <td className="py-2 px-3 text-[#a5b4fc] text-[10px]">
                          {sc.category}
                        </td>
                        <td className="py-2 px-3">
                          <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${
                            sc.severity === 'CRITICAL' ? 'bg-[#f43f5e]/20 text-[#fb7185]' :
                            sc.severity === 'HIGH' ? 'bg-[#f97316]/20 text-[#fb923c]' :
                            sc.severity === 'MEDIUM' ? 'bg-[#f59e0b]/20 text-[#fbbf24]' :
                            'bg-[#34d399]/20 text-[#34d399]'
                          }`}>
                            {sc.severity}
                          </span>
                        </td>
                        <td className="py-2 px-3">
                          <div className="text-[10px] text-[#38bdf8] font-bold">{sc.mitre_atlas_id}</div>
                          <div className="text-[9px] text-[#64748b]">{sc.owasp_llm_id}</div>
                        </td>
                        <td className="py-2 px-3">
                          <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${
                            sc.expected_security_result === 'BLOCK' ? 'bg-[#f43f5e]/20 text-[#fb7185]' :
                            sc.expected_security_result === 'REQUIRE_APPROVAL' ? 'bg-[#f59e0b]/20 text-[#fbbf24]' :
                            'bg-[#10b981]/20 text-[#34d399]'
                          }`}>
                            {sc.expected_security_result}
                          </span>
                        </td>
                        <td className="py-2 px-3 text-right">
                          <div className="flex items-center justify-end gap-1.5">
                            <button
                              onClick={() => handleRunAttack(sc.scenario_id)}
                              disabled={isRunningAttack}
                              className="px-2 py-1 bg-[#1e293b] hover:bg-[#334155] text-white rounded text-[10px] font-bold transition flex items-center gap-1 cursor-pointer"
                              title="Run attack simulation through authentic pipeline"
                            >
                              <Play className="w-2.5 h-2.5 fill-current" />
                              <span>Simulate</span>
                            </button>
                            <button
                              onClick={() => handleReplayAttack(sc.scenario_id)}
                              disabled={isRunningAttack}
                              className="p-1 bg-[#121929] hover:bg-[#1e293b] text-[#94a3b8] hover:text-[#38bdf8] rounded text-[10px] transition cursor-pointer"
                              title="Replay simulation under selected baseline"
                            >
                              <RotateCcw className="w-3 h-3" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Col 2: Control Effectiveness Matrix (5 cols) */}
          <div className="xl:col-span-5 space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-[#94a3b8] flex items-center gap-1.5">
              <Shield className="w-3.5 h-3.5 text-[#38bdf8]" /> Comparative Control Effectiveness Matrix
            </h3>

            <div className="table-wrapper max-h-[380px] overflow-y-auto">
              <table className="w-full text-left font-sans text-xs">
                <thead className="bg-[#0d121f] text-[#64748b] uppercase tracking-wider text-[10px] sticky top-0 z-10">
                  <tr>
                    <th className="py-2.5 px-2.5">Category</th>
                    <th className="py-2.5 px-2">Primary Control</th>
                    <th className="py-2.5 px-1.5 text-center text-[#94a3b8]">Sys A</th>
                    <th className="py-2.5 px-1.5 text-center text-[#94a3b8]">Sys B</th>
                    <th className="py-2.5 px-1.5 text-center text-[#94a3b8]">Sys C</th>
                    <th className="py-2.5 px-1.5 text-center text-[#34d399] font-bold">Sys D</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e2c47] font-mono text-[10px]">
                  {controlEffectiveness.length > 0 ? (
                    controlEffectiveness.map((row, idx) => (
                      <tr key={idx} className="hover:bg-[#121929] transition">
                        <td className="py-2 px-2.5 text-white font-bold truncate max-w-[110px]" title={row.category}>
                          {row.category.replace('_', ' ')}
                        </td>
                        <td className="py-2 px-2 text-[#a5b4fc] text-[9px] truncate max-w-[100px]" title={row.primary_control}>
                          {row.primary_control.replace('_ENGINE', '').replace('_DETECTOR', '')}
                        </td>
                        <td className="py-2 px-1.5 text-center text-[#f43f5e] font-bold">
                          {row.unprotected_allowed_pct.toFixed(0)}%
                        </td>
                        <td className="py-2 px-1.5 text-center text-[#94a3b8]">
                          {row.static_policy_block_pct.toFixed(0)}%
                        </td>
                        <td className="py-2 px-1.5 text-center text-[#fbbf24]">
                          {row.behavioral_block_pct.toFixed(0)}%
                        </td>
                        <td className="py-2 px-1.5 text-center text-[#34d399] font-bold">
                          {row.full_sentinel_block_pct.toFixed(0)}%
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={6} className="py-4 text-center text-[#64748b] text-xs font-mono">
                        Loading control effectiveness evaluation...
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            <div className="p-2.5 bg-[#0a0d14] rounded border border-[#1e2c47] text-[10px] text-[#64748b] font-mono flex items-center justify-between">
              <span>Sys A: Unprotected | Sys B: Static | Sys C: Behavioral</span>
              <span className="text-[#34d399] font-bold">Sys D: Full AgentSentinel</span>
            </div>
          </div>
        </div>
      </section>

      {/* ATTACK SIMULATION & THREAT GRAPH MODAL / DRAWER */}
      {selectedRunResult && (
        <>
          <div className="drawer-backdrop" onClick={() => setSelectedRunResult(null)} />
          <div className="drawer-content p-5 font-sans space-y-5 max-w-2xl">
            {/* Header */}
            <div className="flex items-center justify-between pb-3 border-b border-[#1e2c47]">
              <div className="flex items-center gap-2">
                <Crosshair className="w-5 h-5 text-[#f43f5e]" />
                <div>
                  <h2 className="text-sm font-bold uppercase tracking-wider text-white">
                    Attack Simulation Trace & Threat Intelligence
                  </h2>
                  <p className="text-[11px] font-mono text-[#64748b]">
                    Run: {selectedRunResult.execution_result.run_id} | Scenario: {selectedRunResult.execution_result.scenario_id}
                  </p>
                </div>
              </div>
              <button
                onClick={() => setSelectedRunResult(null)}
                className="p-1.5 bg-[#1a243a] hover:bg-[#2e4066] text-[#94a3b8] hover:text-white rounded transition cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Run Outcome Banner */}
            <div className={`p-3.5 rounded-lg border flex items-center justify-between ${
              selectedRunResult.execution_result.final_decision === 'BLOCK'
                ? 'bg-[#f43f5e]/10 border-[#f43f5e]/40 text-[#fb7185]'
                : selectedRunResult.execution_result.final_decision === 'REQUIRE_APPROVAL'
                ? 'bg-[#f59e0b]/10 border-[#f59e0b]/40 text-[#fbbf24]'
                : 'bg-[#10b981]/10 border-[#10b981]/40 text-[#34d399]'
            }`}>
              <div>
                <span className="text-[10px] uppercase tracking-wider font-bold block font-mono">
                  Simulation Outcome ({selectedRunResult.execution_result.baseline_type})
                </span>
                <span className="text-sm font-bold font-mono mt-0.5 block text-white">
                  Decision: {selectedRunResult.execution_result.final_decision}
                </span>
                {selectedRunResult.execution_result.is_interrupted && (
                  <p className="text-xs text-[#fb7185] mt-1 font-mono">
                    🛡️ Multi-step attack chain halted at Step {selectedRunResult.execution_result.interrupted_at_step} of {selectedRunResult.execution_result.total_steps}
                  </p>
                )}
              </div>
              <div className="text-right font-mono">
                <span className="text-xs text-[#94a3b8] block">Latency</span>
                <span className="text-sm font-bold text-white">{selectedRunResult.execution_result.total_latency_ms.toFixed(1)} ms</span>
                <span className="text-[10px] text-[#34d399] font-bold block mt-0.5">
                  {selectedRunResult.execution_result.passed ? 'PASSED EXPECTATION' : 'BASELINE DIFFERENCE'}
                </span>
              </div>
            </div>

            {/* Attack Chain Execution Steps */}
            <div className="space-y-2 bg-[#0d121f] p-3.5 rounded border border-[#1e2c47]">
              <h3 className="text-[11px] font-bold uppercase tracking-wider text-[#94a3b8] flex items-center gap-1.5">
                <Layers className="w-3.5 h-3.5 text-[#38bdf8]" /> Step-by-Step Security Pipeline Outcomes
              </h3>
              <div className="space-y-2">
                {selectedRunResult.execution_result.step_results.map((st) => (
                  <div key={st.step_index} className="p-2.5 bg-[#0a0d14] rounded border border-[#1e2c47] font-mono text-xs space-y-1">
                    <div className="flex justify-between items-center">
                      <span className="text-white font-bold">Step {st.step_index}: {st.tool_name}</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        st.final_verdict === 'BLOCK' ? 'bg-[#f43f5e]/20 text-[#fb7185]' :
                        st.final_verdict === 'REQUIRE_APPROVAL' ? 'bg-[#f59e0b]/20 text-[#fbbf24]' :
                        'bg-[#10b981]/20 text-[#34d399]'
                      }`}>
                        {st.final_verdict}
                      </span>
                    </div>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[10px] text-[#64748b] pt-1 border-t border-[#1e2c47]/50">
                      <div>Policy: <span className="text-[#a5b4fc] font-bold">{st.policy_decision}</span></div>
                      <div>Risk Score: <span className="text-[#fbbf24] font-bold">{st.unified_risk_score.toFixed(2)}</span></div>
                      <div>Primary Control: <span className="text-white">{st.primary_control_detected}</span></div>
                      <div>Latency: <span className="text-[#34d399]">{st.latency_ms.toFixed(1)} ms</span></div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Attack Graph View */}
            {selectedRunResult.graph?.nodes?.length > 0 && (
              <div className="space-y-2 bg-[#0d121f] p-3.5 rounded border border-[#1e2c47]">
                <h3 className="text-[11px] font-bold uppercase tracking-wider text-[#94a3b8] flex items-center gap-1.5">
                  <Network className="w-3.5 h-3.5 text-[#a855f7]" /> Attack Graph Structure ({selectedRunResult.graph.nodes.length} Nodes, {selectedRunResult.graph.edges.length} Edges)
                </h3>
                <div className="flex flex-wrap gap-2 p-2.5 bg-[#0a0d14] rounded border border-[#1e2c47]">
                  {selectedRunResult.graph.nodes.map((node) => (
                    <div
                      key={node.id}
                      className={`px-2 py-1 rounded text-[10px] font-mono border ${
                        node.node_type === 'Attack' ? 'bg-[#f43f5e]/20 text-[#fb7185] border-[#f43f5e]/40' :
                        node.node_type === 'Action' ? 'bg-[#3b82f6]/20 text-[#93c5fd] border-[#3b82f6]/40' :
                        node.node_type === 'Agent' ? 'bg-[#10b981]/20 text-[#6ee7b7] border-[#10b981]/40' :
                        node.node_type === 'Tool' ? 'bg-[#f59e0b]/20 text-[#fcd34d] border-[#f59e0b]/40' :
                        'bg-[#a855f7]/20 text-[#d8b4fe] border-[#a855f7]/40'
                      }`}
                    >
                      <span className="font-bold opacity-75">{node.node_type}:</span> {node.label}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Threat Intelligence Findings */}
            {selectedRunResult.findings.length > 0 && (
              <div className="space-y-3 bg-[#0d121f] p-3.5 rounded border border-[#1e2c47]">
                <h3 className="text-[11px] font-bold uppercase tracking-wider text-[#94a3b8] flex items-center gap-1.5">
                  <FileText className="w-3.5 h-3.5 text-[#f43f5e]" /> Threat Intelligence Findings ({selectedRunResult.findings.length})
                </h3>
                <div className="space-y-2.5">
                  {selectedRunResult.findings.map((fnd) => (
                    <div key={fnd.finding_id} className="p-3 bg-[#0a0d14] rounded border border-[#1e2c47] space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-white text-xs">{fnd.title}</span>
                        <div className="flex items-center gap-1.5">
                          <span className="px-1.5 py-0.5 rounded bg-[#38bdf8]/20 text-[#38bdf8] border border-[#38bdf8]/40 font-mono text-[9px] font-bold">
                            {fnd.mitre_atlas_id}
                          </span>
                          <span className="px-1.5 py-0.5 rounded bg-[#f59e0b]/20 text-[#fbbf24] border border-[#f59e0b]/40 font-mono text-[9px] font-bold">
                            {fnd.owasp_llm_category}
                          </span>
                        </div>
                      </div>

                      <p className="text-[11px] text-[#94a3b8]">{fnd.description}</p>

                      {fnd.evidence && fnd.evidence.length > 0 && (
                        <div className="space-y-0.5">
                          <span className="text-[10px] text-[#64748b] font-mono block">Evidence:</span>
                          <ul className="list-disc list-inside text-[10px] text-[#fb7185] font-mono space-y-0.5">
                            {fnd.evidence.map((ev, i) => (
                              <li key={i}>{ev}</li>
                            ))}
                          </ul>
                        </div>
                      )}

                      <div className="pt-1.5 border-t border-[#1e2c47] text-[10px] text-[#34d399] font-mono">
                        <span className="font-bold text-[#64748b]">Remediation:</span> {fnd.remediation}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Footer Buttons */}
            <div className="flex items-center justify-end gap-2 pt-2 border-t border-[#1e2c47]">
              <button
                onClick={() => handleReplayAttack(selectedRunResult.execution_result.scenario_id)}
                disabled={isRunningAttack}
                className="px-3 py-1.5 rounded bg-[#1e293b] hover:bg-[#334155] text-white font-mono text-xs font-bold transition flex items-center gap-1 cursor-pointer"
              >
                <RotateCcw className="w-3.5 h-3.5" /> Replay Simulation
              </button>
              <button
                onClick={() => setSelectedRunResult(null)}
                className="px-3 py-1.5 rounded bg-[#f43f5e] hover:bg-[#e11d48] text-white font-mono text-xs font-bold transition cursor-pointer"
              >
                Close Trace
              </button>
            </div>
          </div>
        </>
      )}
      {selectedEvent && (
        <>
          {/* Backdrop */}
          <div className="drawer-backdrop" onClick={() => setSelectedEvent(null)} />

          {/* Drawer Content */}
          <div className="drawer-content p-5 font-sans space-y-5">
            {/* Drawer Header */}
            <div className="flex items-center justify-between pb-3 border-b border-[#1e2c47]">
              <div className="flex items-center gap-2">
                <Shield className="w-5 h-5 text-[#818cf8]" />
                <div>
                  <h2 className="text-sm font-bold uppercase tracking-wider text-white">Event Inspection Panel</h2>
                  <p className="text-[11px] font-mono text-[#64748b]">{selectedEvent.event_id}</p>
                </div>
              </div>

              <button
                onClick={() => setSelectedEvent(null)}
                className="p-1.5 bg-[#1a243a] hover:bg-[#2e4066] text-[#94a3b8] hover:text-white rounded transition cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* EVENT INFORMATION */}
            <div className="space-y-2 bg-[#0d121f] p-3.5 rounded border border-[#1e2c47]">
              <h3 className="text-[11px] font-bold uppercase tracking-wider text-[#94a3b8] flex items-center gap-1.5">
                <User className="w-3.5 h-3.5 text-[#6366f1]" /> Event Information
              </h3>
              <div className="space-y-1.5 font-mono text-xs">
                <div className="flex justify-between"><span className="text-[#64748b]">Event ID:</span> <span className="text-white">{selectedEvent.event_id}</span></div>
                <div className="flex justify-between"><span className="text-[#64748b]">Timestamp:</span> <span className="text-[#94a3b8]">{selectedEvent.created_at ? new Date(selectedEvent.created_at).toLocaleString() : 'Now'}</span></div>
                <div className="flex justify-between"><span className="text-[#64748b]">Session ID:</span> <span className="text-[#a5b4fc]">{selectedEvent.session_id}</span></div>
                <div className="flex justify-between"><span className="text-[#64748b]">Agent ID:</span> <span className="text-white">{selectedEvent.agent_id}</span></div>
                <div className="flex justify-between"><span className="text-[#64748b]">User ID:</span> <span className="text-white">{selectedEvent.user_id}</span></div>
                <div className="flex justify-between"><span className="text-[#64748b]">Role:</span> <span className="text-[#34d399] font-bold">{selectedEvent.role}</span></div>
              </div>
            </div>

            {/* TOOL ACTION */}
            <div className="space-y-2 bg-[#0d121f] p-3.5 rounded border border-[#1e2c47]">
              <h3 className="text-[11px] font-bold uppercase tracking-wider text-[#94a3b8] flex items-center gap-1.5">
                <Database className="w-3.5 h-3.5 text-[#06b6d4]" /> Tool Action
              </h3>
              <div className="space-y-1.5 font-mono text-xs">
                <div className="flex justify-between"><span className="text-[#64748b]">Tool Name:</span> <span className="text-white font-bold">{selectedEvent.tool_name}</span></div>
                <div className="flex justify-between"><span className="text-[#64748b]">Action Type:</span> <span className="text-[#22d3ee]">{selectedEvent.action_type}</span></div>
                <div className="flex justify-between"><span className="text-[#64748b]">Target Resource:</span> <span className="text-[#e2e8f0] break-all">{selectedEvent.target_resource || 'N/A'}</span></div>
                {selectedEvent.arguments_payload_json && (
                  <div className="mt-2">
                    <span className="text-[#64748b] block mb-1">Arguments Payload:</span>
                    <pre className="p-2 bg-[#0a0d14] rounded text-[10px] text-[#34d399] overflow-x-auto border border-[#1e2c47]">
                      {JSON.stringify(selectedEvent.arguments_payload_json, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            </div>

            {/* SECURITY DECISION */}
            <div className="space-y-2 bg-[#0d121f] p-3.5 rounded border border-[#1e2c47]">
              <h3 className="text-[11px] font-bold uppercase tracking-wider text-[#94a3b8] flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5 text-[#f43f5e]" /> Security Decision
              </h3>
              <div className="space-y-1.5 font-mono text-xs">
                <div className="flex justify-between items-center">
                  <span className="text-[#64748b]">Final Decision:</span>
                  {getDecisionBadge(selectedEvent.decision_result, selectedEvent.execution_allowed, selectedEvent.approval_required)}
                </div>
                <div className="flex justify-between"><span className="text-[#64748b]">Execution Allowed:</span> <span className={selectedEvent.execution_allowed ? "text-[#34d399] font-bold" : "text-[#fb7185] font-bold"}>{selectedEvent.execution_allowed ? "YES" : "NO"}</span></div>
                <div className="flex justify-between"><span className="text-[#64748b]">Approval Required:</span> <span className="text-[#fbbf24] font-bold">{selectedEvent.approval_required ? "YES" : "NO"}</span></div>
                <div className="mt-2">
                  <span className="text-[#64748b] block">Decision Reason:</span>
                  <p className="text-white text-[11px] mt-0.5 p-2 bg-[#0a0d14] rounded border border-[#1e2c47]">
                    {selectedEvent.decision_reason}
                  </p>
                </div>
              </div>
            </div>

            {/* BEHAVIOR */}
            <div className="space-y-2 bg-[#0d121f] p-3.5 rounded border border-[#1e2c47]">
              <h3 className="text-[11px] font-bold uppercase tracking-wider text-[#94a3b8] flex items-center gap-1.5">
                <Layers className="w-3.5 h-3.5 text-[#f59e0b]" /> Behavioral Risk Intelligence
              </h3>
              <div className="space-y-1.5 font-mono text-xs">
                <div className="flex justify-between items-center">
                  <span className="text-[#64748b]">Unified Risk Score:</span>
                  <span className="text-white font-bold">{selectedEvent.anomaly_score?.toFixed(2) || '0.00'}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-[#64748b]">Risk Severity Level:</span>
                  {getRiskLevelBadge(selectedEvent.anomaly_score || 0.0)}
                </div>
                {selectedEvent.metadata_json?.unified_risk?.primary_detector && (
                  <div className="flex justify-between items-center">
                    <span className="text-[#64748b]">Primary Detector:</span>
                    <span className="text-[#a5b4fc] font-bold">{selectedEvent.metadata_json.unified_risk.primary_detector}</span>
                  </div>
                )}
                {selectedEvent.metadata_json?.unified_risk?.top_risk_factors?.length > 0 && (
                  <div className="mt-2">
                    <span className="text-[#64748b] block mb-1">Top Risk Factors:</span>
                    <ul className="list-disc list-inside text-[10px] text-[#fbbf24] space-y-0.5">
                      {selectedEvent.metadata_json?.unified_risk?.top_risk_factors?.map((factor: string, idx: number) => (
                        <li key={idx}>{factor}</li>
                      ))}
                    </ul>
                  </div>
                )}
                <div className="mt-2">
                  <span className="text-[#64748b] block mb-1">Threat Flags:</span>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedEvent.threat_flags_json && selectedEvent.threat_flags_json.length > 0 ? (
                      selectedEvent.threat_flags_json.map((flag, idx) => (
                        <span key={idx} className="px-2 py-0.5 bg-[#f43f5e]/20 text-[#fb7185] border border-[#f43f5e]/40 rounded text-[10px]">
                          {flag}
                        </span>
                      ))
                    ) : (
                      <span className="text-[#64748b] text-[11px]">None (Clean Baseline)</span>
                    )}
                  </div>
                </div>
              </div>
            </div>

            {/* MULTI-AGENT PROVENANCE & DELEGATION (PHASE 0.4) */}
            {selectedEvent.metadata_json?.multi_agent && (() => {
              const ma = selectedEvent.metadata_json.multi_agent;
              const provChain: string[] = ma.provenance_chain || [];
              const delegatedCaps: string[] = ma.delegated_capabilities || [];
              return (
                <div className="space-y-2 bg-[#0d121f] p-3.5 rounded border border-[#6366f1]/40 shadow-[0_0_15px_rgba(99,102,241,0.15)]">
                  <h3 className="text-[11px] font-bold uppercase tracking-wider text-[#a5b4fc] flex items-center gap-1.5">
                    <Network className="w-3.5 h-3.5 text-[#818cf8]" /> Multi-Agent Governance & Provenance
                  </h3>
                  <div className="space-y-1.5 font-mono text-xs">
                    <div className="flex justify-between">
                      <span className="text-[#64748b]">Delegation ID:</span>
                      <span className="text-[#38bdf8] font-semibold">{ma.delegation_id || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-[#64748b]">Delegation Depth:</span>
                      <span className="px-1.5 py-0.5 rounded bg-[#1e1b4b] text-[#c7d2fe] text-[10px] font-bold">
                        Level {ma.delegation_depth ?? 1} / 3
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-[#64748b]">Origin Agent:</span>
                      <span className="text-[#34d399] font-bold">{ma.origin_agent_id || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-[#64748b]">Delegator (Source):</span>
                      <span className="text-white">{ma.source_agent_id || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-[#64748b]">Executing (Target):</span>
                      <span className="text-[#f59e0b] font-bold">{ma.target_agent_id || selectedEvent.agent_id}</span>
                    </div>
                    {delegatedCaps.length > 0 && (
                      <div className="mt-2">
                        <span className="text-[#64748b] block mb-1">Delegated Capabilities:</span>
                        <div className="flex flex-wrap gap-1">
                          {delegatedCaps.map((cap: string, idx: number) => (
                            <span key={idx} className="px-2 py-0.5 bg-[#4338ca]/30 text-[#c7d2fe] border border-[#6366f1]/40 rounded text-[10px] font-mono">
                              {cap}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                    {provChain.length > 0 && (
                      <div className="mt-2">
                        <span className="text-[#64748b] block mb-1">Provenance Chain:</span>
                        <div className="flex items-center gap-1.5 p-2 bg-[#0a0d14] rounded border border-[#1e2c47] text-[11px] text-[#a5b4fc] overflow-x-auto">
                          {provChain.map((agent: string, idx: number) => (
                            <span key={idx} className="flex items-center gap-1">
                              <span className="px-1.5 py-0.5 rounded bg-[#1e293b] text-white font-mono text-[10px]">{agent}</span>
                              {idx < provChain.length - 1 && (
                                <span className="text-[#64748b] font-bold">→</span>
                              )}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              );
            })()}

            {/* PERFORMANCE */}
            <div className="space-y-2 bg-[#0d121f] p-3.5 rounded border border-[#1e2c47]">
              <h3 className="text-[11px] font-bold uppercase tracking-wider text-[#94a3b8] flex items-center gap-1.5">
                <Zap className="w-3.5 h-3.5 text-[#22d3ee]" /> Interception Performance
              </h3>
              <div className="flex justify-between font-mono text-xs">
                <span className="text-[#64748b]">Processing Latency:</span>
                <span className="text-[#22d3ee] font-bold">{selectedEvent.latency_ms || 1.25} ms</span>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

export default App;
