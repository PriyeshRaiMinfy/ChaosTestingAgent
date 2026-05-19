import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import Layout from '../components/Layout'

interface ScanSummary {
  scan_id: string
  resource_count: number
  accounts_scanned: string[]
  regions_scanned: string[]
  posture_summary: Record<string, number>
  trail_event_count: number
  has_report: boolean
}

interface AttackPath {
  name: string
  severity: string
  confidence: string
  steps: string[]
  blastRadius: string
  remediation: string[]
}

interface ReportData {
  overallSeverity: string
  summary: string
  topRisks: string[]
  attackPaths: AttackPath[]
  raw: string
}

function stripMd(s: string) {
  return s.replace(/\*+/g, '').replace(/^#+\s*/, '').trim()
}

function parseReport(md: string): ReportData {
  const lines = md.split('\n').map(l => l.trim()).filter(Boolean)

  let overallSeverity = ''
  let summary = ''
  const topRisks: string[] = []
  const attackPaths: AttackPath[] = []

  let i = 0
  while (i < lines.length) {
    const line = lines[i]
    const clean = stripMd(line)

    if (clean.match(/^overall severity[:\s]+(.+)/i)) {
      overallSeverity = clean.replace(/^overall severity[:\s]+/i, '').trim()
    } else if (clean.match(/^summary$/i)) {
      i++
      const summaryLines: string[] = []
      while (i < lines.length && !stripMd(lines[i]).match(/^(top risks?|attack paths|path \d+)/i) && !lines[i].match(/^##/)) {
        summaryLines.push(stripMd(lines[i]))
        i++
      }
      summary = summaryLines.join(' ')
      continue
    } else if (clean.match(/^top risks?$/i)) {
      i++
      while (i < lines.length && !stripMd(lines[i]).match(/^(attack paths|path \d+)/i) && !lines[i].match(/^##/)) {
        const risk = stripMd(lines[i]).replace(/^[\d.\-*•]\s*/, '').trim()
        if (risk) topRisks.push(risk)
        i++
      }
      continue
    } else if (clean.match(/^path \d+:/i)) {
      const nameMatch = clean.match(/path \d+:\s*(.+)/i)
      const name = nameMatch ? nameMatch[1].replace(/\[.*?\]/g, '').trim() : clean
      const sevMatch = clean.match(/\[(CRITICAL|HIGH|MEDIUM|LOW)\]/i)
      const severity = sevMatch ? sevMatch[1].toUpperCase() : 'HIGH'

      let confidence = ''
      const steps: string[] = []
      let blastRadius = ''
      const remediation: string[] = []
      let section = ''

      i++
      while (i < lines.length && !stripMd(lines[i]).match(/^path \d+:/i)) {
        const l = lines[i]
        const c = stripMd(l)

        if (c.match(/^confidence[:\s]+(.+)/i)) {
          confidence = c.replace(/^confidence[:\s]+/i, '').trim()
          section = ''
        } else if (c.match(/^attack steps?[:\s]*$/i)) {
          section = 'steps'
        } else if (c.match(/^blast radius[:\s]*(.*)/i)) {
          section = 'blast'
          const val = c.replace(/^blast radius[:\s]*/i, '').trim()
          if (val) blastRadius = val
        } else if (c.match(/^remediation[:\s]*$/i)) {
          section = 'remediation'
        } else if (section === 'steps') {
          const step = c.replace(/^[\d]+\.\s*/, '').replace(/^[\-*•]\s*/, '').trim()
          if (step && !step.match(/^(confidence|blast radius|remediation)/i)) steps.push(step)
        } else if (section === 'blast' && !blastRadius) {
          blastRadius = c.replace(/^[\-*•]\s*/, '').trim()
        } else if (section === 'remediation') {
          const rem = c.replace(/^[\d.\-*•]\s*/, '').trim()
          if (rem) remediation.push(rem)
        }
        i++
      }

      attackPaths.push({ name, severity, confidence, steps, blastRadius, remediation })
      continue
    }
    i++
  }

  return { overallSeverity, summary, topRisks, attackPaths, raw: md }
}

const SEV_COLOR: Record<string, string> = {
  CRITICAL: 'text-rose-400 border-rose-500/30 bg-rose-500/5',
  HIGH: 'text-amber-400 border-amber-500/30 bg-amber-500/5',
  MEDIUM: 'text-yellow-300 border-yellow-500/30 bg-yellow-500/5',
  LOW: 'text-emerald-400 border-emerald-500/30 bg-emerald-500/5',
}
const SEV_BADGE: Record<string, string> = {
  CRITICAL: 'bg-rose-500/20 text-rose-300',
  HIGH: 'bg-amber-500/20 text-amber-300',
  MEDIUM: 'bg-yellow-500/20 text-yellow-200',
  LOW: 'bg-emerald-500/20 text-emerald-300',
}

export default function Results() {
  const { scanId } = useParams()
  const navigate = useNavigate()
  const [summary, setSummary] = useState<ScanSummary | null>(null)
  const [reportData, setReportData] = useState<ReportData | null>(null)
  const [posture, setPosture] = useState<any[] | null>(null)
  const [activeTab, setActiveTab] = useState<'summary' | 'report' | 'posture'>('summary')
  const [loading, setLoading] = useState(true)
  const [expandedPath, setExpandedPath] = useState<number | null>(null)

  useEffect(() => {
    fetch(`/api/scan/${scanId}/summary`)
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (d) setSummary(d) })
      .finally(() => setLoading(false))
  }, [scanId])

  const fetchReport = async () => {
    if (reportData) return
    const resp = await fetch(`/api/scan/${scanId}/report`)
    if (resp.ok) {
      const data = await resp.json()
      setReportData(parseReport(data.content))
    }
  }

  const fetchPosture = async () => {
    if (posture) return
    const resp = await fetch(`/api/scan/${scanId}/posture`)
    if (resp.ok) setPosture(await resp.json())
  }

  const handleTabChange = (tab: typeof activeTab) => {
    setActiveTab(tab)
    if (tab === 'report') fetchReport()
    if (tab === 'posture') fetchPosture()
  }

  if (loading) {
    return <Layout breadcrumbs={['Results']}><div className="flex items-center justify-center h-64 text-slate-500">Loading...</div></Layout>
  }

  return (
    <Layout breadcrumbs={['Results', scanId || '']} scanId={summary?.accounts_scanned?.[0]}>
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-start justify-between mb-6">
          <div>
            <h1 className="text-2xl font-black text-white">Scan Report</h1>
            <p className="text-sm text-slate-400 mt-1 font-mono">{scanId}</p>
          </div>
          <button onClick={() => navigate(`/graph/${scanId}`)}
            className="px-5 py-2 bg-[#4f46e5] text-white font-semibold text-sm rounded hover:bg-[#4338ca] transition">
            View Graph
          </button>
        </div>

        {summary && (
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-6">
            <StatBox label="Resources" value={String(summary.resource_count)} />
            <StatBox label="Accounts" value={String(summary.accounts_scanned.length)} />
            <StatBox label="Regions" value={String(summary.regions_scanned.length)} />
            <StatBox label="Trail Events" value={String(summary.trail_event_count)} />
            <StatBox label="Report" value={summary.has_report ? 'Generated' : 'Pending'} highlight={summary.has_report} />
          </div>
        )}

        {summary && (
          <div className="border border-white/10 bg-[#0a0e14] rounded p-5 space-y-2">
            {Object.entries(summary.posture_summary).filter(([, c]) => c > 0).map(([sev, count]) => (
              <div key={sev} className="flex items-center gap-4">
                <span className={`text-xs font-bold w-16 ${
                  sev === 'CRITICAL' ? 'text-rose-400' : sev === 'HIGH' ? 'text-amber-400' :
                  sev === 'MEDIUM' ? 'text-yellow-300' : 'text-emerald-400'}`}>{sev}</span>
                <div className="flex-1 h-2 bg-[#0d1117] rounded-full overflow-hidden">
                  <div className={`h-full rounded-full ${
                    sev === 'CRITICAL' ? 'bg-rose-500' : sev === 'HIGH' ? 'bg-amber-500' :
                    sev === 'MEDIUM' ? 'bg-yellow-500' : 'bg-emerald-500'}`}
                    style={{ width: `${Math.min(100, (count / 200) * 100)}%` }} />
                </div>
                <span className="text-xs text-slate-500 w-8 text-right font-mono">{count}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Tabs */}
      <div className="border-b border-white/10 mb-6">
        <div className="flex">
          {(['summary', 'report', 'posture'] as const).map(tab => (
            <button key={tab} onClick={() => handleTabChange(tab)}
              className={`px-5 py-3 text-sm font-medium border-b-2 transition capitalize ${
                activeTab === tab ? 'border-[#818cf8] text-[#818cf8]' : 'border-transparent text-[#555] hover:text-[#999]'}`}>
              {tab === 'report' ? 'Attack Paths' : tab === 'posture' ? 'Posture Findings' : 'Scan Details'}
            </button>
          ))}
        </div>
      </div>

      {/* Attack Paths tab */}
      {activeTab === 'report' && (
        <div>
          {reportData ? (
            <div className="space-y-6">
              {/* Summary card */}
              <div className={`border rounded p-5 ${SEV_COLOR[reportData.overallSeverity] || 'border-white/10 bg-[#0a0e14]'}`}>
                <div className="flex items-center gap-3 mb-3">
                  <span className={`px-2 py-0.5 text-xs font-black rounded ${SEV_BADGE[reportData.overallSeverity] || 'bg-white/10 text-white'}`}>
                    {reportData.overallSeverity || 'UNKNOWN'} OVERALL
                  </span>
                </div>
                <p className="text-sm text-slate-300 leading-6">{reportData.summary}</p>
              </div>

              {/* Top risks */}
              {reportData.topRisks.length > 0 && (
                <div className="border border-white/10 bg-[#0a0e14] rounded p-5">
                  <div className="text-[10px] font-bold uppercase tracking-[0.2em] text-slate-500 mb-3">// Top Risks</div>
                  <ul className="space-y-2">
                    {reportData.topRisks.map((r, i) => (
                      <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
                        <span className="text-amber-400 mt-0.5 shrink-0">▸</span>
                        {r}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Attack path cards */}
              <div className="text-[10px] font-bold uppercase tracking-[0.2em] text-slate-500 mb-2">
                // Attack Paths ({reportData.attackPaths.length})
              </div>
              <div className="space-y-3">
                {reportData.attackPaths.map((path, i) => (
                  <div key={i} className={`border rounded overflow-hidden ${SEV_COLOR[path.severity] || 'border-white/10 bg-[#0a0e14]'}`}>
                    <button
                      onClick={() => setExpandedPath(expandedPath === i ? null : i)}
                      className="w-full flex items-center justify-between px-5 py-4 text-left hover:bg-white/[0.02] transition"
                    >
                      <div className="flex items-center gap-3">
                        <span className="text-slate-500 font-mono text-xs">#{i + 1}</span>
                        <span className="font-bold text-white">{path.name}</span>
                        <span className={`px-2 py-0.5 text-[10px] font-black rounded ${SEV_BADGE[path.severity] || 'bg-white/10 text-white'}`}>
                          {path.severity}
                        </span>
                        {path.confidence && (
                          <span className="text-[10px] text-slate-500 border border-white/10 px-2 py-0.5 rounded">
                            {path.confidence} confidence
                          </span>
                        )}
                      </div>
                      <span className="text-slate-500 text-xs">{expandedPath === i ? '▲' : '▼'}</span>
                    </button>

                    {expandedPath === i && (
                      <div className="px-5 pb-5 space-y-4 border-t border-white/10">
                        {path.steps.length > 0 && (
                          <div className="pt-4">
                            <div className="text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500 mb-2">Attack Steps</div>
                            <ol className="space-y-2">
                              {path.steps.map((s, j) => (
                                <li key={j} className="flex items-start gap-3 text-sm text-slate-300">
                                  <span className="shrink-0 w-5 h-5 rounded-full bg-white/10 flex items-center justify-center text-[10px] font-bold text-slate-400 mt-0.5">
                                    {j + 1}
                                  </span>
                                  {s}
                                </li>
                              ))}
                            </ol>
                          </div>
                        )}

                        {path.blastRadius && (
                          <div className="border border-rose-500/20 bg-rose-500/5 rounded p-3">
                            <div className="text-[10px] font-bold uppercase tracking-[0.18em] text-rose-400 mb-1">Blast Radius</div>
                            <p className="text-sm text-slate-300">{path.blastRadius}</p>
                          </div>
                        )}

                        {path.remediation.length > 0 && (
                          <div className="border border-emerald-500/20 bg-emerald-500/5 rounded p-3">
                            <div className="text-[10px] font-bold uppercase tracking-[0.18em] text-emerald-400 mb-2">Remediation</div>
                            <ul className="space-y-1">
                              {path.remediation.map((r, j) => (
                                <li key={j} className="flex items-start gap-2 text-sm text-slate-300">
                                  <span className="text-emerald-400 shrink-0 mt-0.5">✓</span>
                                  {r}
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="text-slate-500 text-center py-12">
              {summary?.has_report ? 'Loading report...' : 'No report generated yet.'}
            </div>
          )}
        </div>
      )}

      {/* Posture findings tab */}
      {activeTab === 'posture' && (
        <div className="border border-white/10 bg-[#0a0e14] rounded overflow-hidden">
          {posture ? (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-white/10 text-slate-500">
                  <th className="px-4 py-3 text-left text-[10px] font-bold uppercase tracking-[0.18em]">Severity</th>
                  <th className="px-4 py-3 text-left text-[10px] font-bold uppercase tracking-[0.18em]">Domain</th>
                  <th className="px-4 py-3 text-left text-[10px] font-bold uppercase tracking-[0.18em]">Finding</th>
                  <th className="px-4 py-3 text-left text-[10px] font-bold uppercase tracking-[0.18em]">Resource</th>
                </tr>
              </thead>
              <tbody>
                {posture.slice(0, 100).map((f, i) => (
                  <tr key={i} className="border-b border-white/5 hover:bg-white/[0.02]">
                    <td className="px-4 py-2">
                      <span className={`text-xs font-bold ${
                        f.severity === 'CRITICAL' ? 'text-rose-400' : f.severity === 'HIGH' ? 'text-amber-400' :
                        f.severity === 'MEDIUM' ? 'text-yellow-300' : 'text-emerald-400'}`}>{f.severity}</span>
                    </td>
                    <td className="px-4 py-2 text-slate-500">{f.domain}</td>
                    <td className="px-4 py-2 text-slate-200">{f.title}</td>
                    <td className="px-4 py-2 text-slate-500 font-mono text-xs truncate max-w-[200px]">{f.resource_name}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="text-slate-500 text-center py-12">Loading posture findings...</div>
          )}
        </div>
      )}

      {/* Scan details tab */}
      {activeTab === 'summary' && summary && (
        <div className="border border-white/10 bg-[#0a0e14] rounded p-6">
          <div className="grid grid-cols-2 gap-4 text-sm">
            <InfoRow label="Account(s)" value={summary.accounts_scanned.join(', ')} />
            <InfoRow label="Region(s)" value={summary.regions_scanned.join(', ')} />
            <InfoRow label="Resources" value={String(summary.resource_count)} />
            <InfoRow label="Trail Events" value={String(summary.trail_event_count)} />
          </div>
        </div>
      )}
    </Layout>
  )
}

function StatBox({ label, value, highlight }: { label: string; value: string; highlight?: boolean }) {
  return (
    <div className="border border-white/10 bg-[#0a0e14] rounded p-4">
      <div className="text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500">{label}</div>
      <div className={`mt-1 text-lg font-black ${highlight ? 'text-emerald-300' : 'text-white'}`}>{value}</div>
    </div>
  )
}

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-slate-500">{label}</span>
      <span className="text-white font-mono text-xs">{value}</span>
    </div>
  )
}
