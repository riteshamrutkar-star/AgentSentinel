import React, { useState, useEffect, useCallback } from 'react';
import {
  Shield,
  CheckCircle2,
  Ban,
  AlertTriangle,
  Activity,
  RefreshCw,
  Play,
  User,
  Clock,
  Database,
  Lock,
  Cpu,
  Layers,
  Check,
  X,
  ChevronRight,
  Zap,
  Radio,
  FileText
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

      {/* EVENT DETAILS PANEL (RIGHT-SIDE SLIDE-OVER DRAWER) */}
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
                <Layers className="w-3.5 h-3.5 text-[#f59e0b]" /> Behavioral Anomaly Analysis
              </h3>
              <div className="space-y-1.5 font-mono text-xs">
                <div className="flex justify-between items-center">
                  <span className="text-[#64748b]">Anomaly Score:</span>
                  <span className="text-white font-bold">{selectedEvent.anomaly_score?.toFixed(2) || '0.00'}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-[#64748b]">Anomaly Risk Level:</span>
                  {getRiskLevelBadge(selectedEvent.anomaly_score || 0.0)}
                </div>
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
