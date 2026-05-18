import { useState, useEffect, useRef, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import Layout from '../components/Layout'

type Step = 'connect' | 'verify' | 'configure' | 'scan'

interface DiscoveryInfo {
  account_id: string
  is_org: boolean
  regions_enabled: string[]
  org_trail_accessible: boolean
  principal_arn?: string
}

interface HandshakeLog {
  icon: '✓' | '→' | '·' | '✗'
  color: string
  text: string
}

interface DomainProgress {
  domain: string
  count: number
  done: boolean
}

const POLICY_JSON = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "securityhub:GetFindings",
        "organizations:DescribeOrganization",
        "organizations:ListAccounts",
        "ec2:Describe*",
        "iam:Get*",
        "iam:List*",
        "s3:GetBucket*",
        "s3:ListAllMyBuckets",
        "lambda:List*",
        "lambda:GetFunction*",
        "rds:Describe*",
        "eks:Describe*",
        "eks:List*",
        "kms:Describe*",
        "kms:List*",
        "secretsmanager:List*",
        "cloudtrail:LookupEvents",
        "elasticache:Describe*",
        "dynamodb:Describe*",
        "dynamodb:List*",
        "sns:List*",
        "sqs:List*"
      ],
      "Resource": "*"
    }
  ]
}`

const REGION_LIST = [
  // US
  { code: 'us-east-1', name: 'US East (N. Virginia)' },
  { code: 'us-east-2', name: 'US East (Ohio)' },
  { code: 'us-west-1', name: 'US West (N. California)' },
  { code: 'us-west-2', name: 'US West (Oregon)' },
  // Canada
  { code: 'ca-central-1', name: 'Canada (Central)' },
  { code: 'ca-west-1', name: 'Canada (Calgary)' },
  // South America
  { code: 'sa-east-1', name: 'South America (São Paulo)' },
  // Europe
  { code: 'eu-west-1', name: 'Europe (Ireland)' },
  { code: 'eu-west-2', name: 'Europe (London)' },
  { code: 'eu-west-3', name: 'Europe (Paris)' },
  { code: 'eu-central-1', name: 'Europe (Frankfurt)' },
  { code: 'eu-central-2', name: 'Europe (Zurich)' },
  { code: 'eu-north-1', name: 'Europe (Stockholm)' },
  { code: 'eu-south-1', name: 'Europe (Milan)' },
  { code: 'eu-south-2', name: 'Europe (Spain)' },
  // Middle East
  { code: 'me-south-1', name: 'Middle East (Bahrain)' },
  { code: 'me-central-1', name: 'Middle East (UAE)' },
  { code: 'il-central-1', name: 'Israel (Tel Aviv)' },
  // Africa
  { code: 'af-south-1', name: 'Africa (Cape Town)' },
  // Asia Pacific
  { code: 'ap-south-1', name: 'Asia Pacific (Mumbai)' },
  { code: 'ap-south-2', name: 'Asia Pacific (Hyderabad)' },
  { code: 'ap-southeast-1', name: 'Asia Pacific (Singapore)' },
  { code: 'ap-southeast-2', name: 'Asia Pacific (Sydney)' },
  { code: 'ap-southeast-3', name: 'Asia Pacific (Jakarta)' },
  { code: 'ap-southeast-4', name: 'Asia Pacific (Melbourne)' },
  { code: 'ap-southeast-5', name: 'Asia Pacific (Malaysia)' },
  { code: 'ap-northeast-1', name: 'Asia Pacific (Tokyo)' },
  { code: 'ap-northeast-2', name: 'Asia Pacific (Seoul)' },
  { code: 'ap-northeast-3', name: 'Asia Pacific (Osaka)' },
  { code: 'ap-east-1', name: 'Asia Pacific (Hong Kong)' },
]

const DOMAIN_LABELS: Record<string, string> = {
  compute: 'Compute resources',
  networking: 'VPCs & Networking',
  eks: 'EKS Clusters',
  serverless: 'Serverless Functions',
  secrets: 'Secrets & Key Rings',
  identity: 'IAM Configurations',
  data: 'S3 Buckets & RDS',
  waf: 'WAF rules',
  containers: 'ECS Task definitions',
  dns: 'DNS & Route53',
  cdn: 'CloudFront / CDN',
  cognito: 'Cognito User Pools',
  apigateway: 'API Gateways',
  messaging: 'SNS / SQS Messaging',
}

export default function Wizard() {
  const navigate = useNavigate()
  const [step, setStep] = useState<Step>('connect')
  const [authMode, setAuthMode] = useState<'keys' | 'profile'>('keys')
  const [profile, setProfile] = useState('default')
  const [accessKey, setAccessKey] = useState('')
  const [secretKey, setSecretKey] = useState('')
  const [region, setRegion] = useState('ap-south-1')
  const [discovery, setDiscovery] = useState<DiscoveryInfo | null>(null)
  const [selectedRegions, setSelectedRegions] = useState<string[]>(['ap-south-1'])
  const [regionSearch, setRegionSearch] = useState('')
  const [regionDropdownOpen, setRegionDropdownOpen] = useState(false)
  const [trailEnabled, setTrailEnabled] = useState(true)
  const [trailMode, setTrailMode] = useState<'fast' | 'deep' | 'custom'>('fast')
  const [customDays, setCustomDays] = useState(14)
  const [customPages, setCustomPages] = useState(20)
  const [scanId, setScanId] = useState<string | null>(null)
  const [progress, setProgress] = useState(0)
  const [domainProgress, setDomainProgress] = useState<DomainProgress[]>([])
  const [logs, setLogs] = useState<string[]>([])
  const [error, setError] = useState<string | null>(null)
  const [validating, setValidating] = useState(false)
  const [handshakeLogs, setHandshakeLogs] = useState<HandshakeLog[]>([])
  const [connectionVerified, setConnectionVerified] = useState(false)
  const [copied, setCopied] = useState(false)
  const pollRef = useRef<number | null>(null)
  const logEndRef = useRef<HTMLDivElement>(null)

  const breadcrumbs = step === 'connect' ? ['Wizard', 'Connect']
    : step === 'verify' ? ['Wizard', 'Verify']
    : step === 'configure' ? ['Wizard', 'Configure']
    : ['Wizard', 'Scan']

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [logs])

  useEffect(() => {
    if (!regionDropdownOpen) return
    const close = () => setRegionDropdownOpen(false)
    document.addEventListener('click', close)
    return () => document.removeEventListener('click', close)
  }, [regionDropdownOpen])

  const handleCopyPolicy = () => {
    navigator.clipboard.writeText(POLICY_JSON)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const handleConnect = async () => {
    setError(null)
    setValidating(true)
    setHandshakeLogs([])
    setConnectionVerified(false)

    try {
      const body: any = { region }
      if (authMode === 'profile') body.profile = profile
      else { body.access_key_id = accessKey; body.secret_access_key = secretKey }

      // Step 1: Validate
      setHandshakeLogs(prev => [...prev, {
        icon: '→', color: 'text-[#818cf8]',
        text: 'Establishing session with AWS STS...'
      }])

      const ctrl1 = new AbortController()
      const t1 = setTimeout(() => ctrl1.abort(), 25000)
      const resp = await fetch('/api/validate-credentials', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: ctrl1.signal,
      }).finally(() => clearTimeout(t1))

      if (!resp.ok) {
        const data = await resp.json()
        setHandshakeLogs(prev => [...prev, {
          icon: '✗', color: 'text-red-400',
          text: `Authentication failed: ${data.detail || 'Invalid credentials'}`
        }])
        setError(data.detail || 'Validation failed')
        return
      }

      const valData = await resp.json()
      setHandshakeLogs(prev => [...prev, {
        icon: '✓', color: 'text-emerald-400',
        text: `Credentials trusted. Identity ARN established: ${valData.account_id}`
      }])

      // Step 2: Discover
      setHandshakeLogs(prev => [...prev, {
        icon: '→', color: 'text-[#818cf8]',
        text: '[Organizations:DescribeOrganization] Querying organizational architecture context...'
      }])

      const discBody: any = { region }
      if (authMode === 'profile') discBody.profile = profile
      else { discBody.access_key_id = accessKey; discBody.secret_access_key = secretKey }

      const ctrl2 = new AbortController()
      const t2 = setTimeout(() => ctrl2.abort(), 30000)
      const disc = await fetch('/api/discover', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(discBody),
        signal: ctrl2.signal,
      }).finally(() => clearTimeout(t2))

      if (disc.ok) {
        const discData = await disc.json()
        setDiscovery(discData)

        if (discData.is_org) {
          setHandshakeLogs(prev => [...prev, {
            icon: '✓', color: 'text-emerald-400',
            text: `Organization detected. Multi-account mode available.`
          }])
        } else {
          setHandshakeLogs(prev => [...prev, {
            icon: '·', color: 'text-[#6b7280]',
            text: '[DescribeOrganization] AccessDenied — standalone account, no organization bounds.'
          }])
        }

        setConnectionVerified(true)
      }
    } catch (e: any) {
      const msg = e.name === 'AbortError' ? 'Request timed out. Check AWS credentials and network.' : (e.message || 'Connection failed')
      setHandshakeLogs(prev => [...prev, {
        icon: '✗', color: 'text-red-400',
        text: `Connection error: ${msg}`
      }])
      setError(msg)
    } finally {
      setValidating(false)
    }
  }

  const toggleRegion = (code: string) => {
    setSelectedRegions(prev =>
      prev.includes(code) ? prev.filter(r => r !== code) : [...prev, code]
    )
  }

  const filteredRegions = REGION_LIST.filter(r =>
    r.code.includes(regionSearch.toLowerCase()) || r.name.toLowerCase().includes(regionSearch.toLowerCase())
  )

  const handleStartScan = async () => {
    setError(null)
    const body: any = {
      region,
      all_regions: selectedRegions.length === REGION_LIST.length,
      trail_enabled: trailEnabled,
      trail_mode: trailMode,
      trail_regions: selectedRegions.includes('us-east-1')
        ? selectedRegions.join(',')
        : [...selectedRegions, 'us-east-1'].join(','),
    }
    if (authMode === 'profile') body.profile = profile
    else { body.access_key_id = accessKey; body.secret_access_key = secretKey }
    if (trailMode === 'custom') {
      body.trail_days = customDays
      body.trail_max_pages = customPages
    }

    try {
      const resp = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      if (!resp.ok) {
        setError('Failed to start scan')
        return
      }
      const data = await resp.json()
      setScanId(data.scan_id)
      setStep('scan')
      setLogs([`[info] Handshaking multi-region session contexts...`, `[info] Target regions established: ${selectedRegions.join(', ')}`])
      startPolling(data.scan_id)
    } catch (e: any) {
      setError(e.message)
    }
  }

  const startPolling = useCallback((id: string) => {
    const poll = async () => {
      try {
        const resp = await fetch(`/api/scan/${id}/status`)
        if (!resp.ok) return
        const data = await resp.json()

        setProgress(data.progress || 0)

        // Update logs
        if (data.logs && data.logs.length > 0) {
          setLogs(prev => {
            const newLogs = data.logs.filter((l: string) => !prev.includes(l))
            return [...prev, ...newLogs].slice(-200)
          })

          // Parse domain progress from logs
          const domainMap: Record<string, { count: number; done: boolean }> = {}
          for (const log of data.logs) {
            const match = log.match(/\[(\w+)\] .+?(\d+) assets/)
            if (match) {
              const [, domain, count] = match
              domainMap[domain] = { count: parseInt(count), done: true }
            }
          }
          if (data.current_domain && !domainMap[data.current_domain]) {
            domainMap[data.current_domain] = { count: 0, done: false }
          }
          const entries = Object.entries(domainMap).map(([domain, v]) => ({ domain, ...v }))
          if (entries.length > 0) setDomainProgress(entries)
        }

        if (data.status === 'completed') {
          setProgress(100)
          setDomainProgress(prev => prev.map(d => ({ ...d, done: true })))
          if (pollRef.current) window.clearInterval(pollRef.current)
        }
        if (data.status === 'failed') {
          setError('Scan failed. Check backend logs.')
          if (pollRef.current) window.clearInterval(pollRef.current)
        }
      } catch { /* retry next interval */ }
    }

    poll()
    pollRef.current = window.setInterval(poll, 2000)
  }, [])

  useEffect(() => {
    return () => { if (pollRef.current) window.clearInterval(pollRef.current) }
  }, [])

  return (
    <Layout breadcrumbs={breadcrumbs} scanId={discovery?.account_id}>
      {error && (
        <div className="mb-6 p-3 border border-red-900/50 bg-red-950/30 rounded text-red-300 text-sm">
          {error}
        </div>
      )}

      {/* ═══════════════ Step 1: Connect ═══════════════ */}
      {step === 'connect' && (
        <div>
          <h1 className="text-xl font-semibold text-white mb-1">Link Your AWS Environment</h1>
          <p className="text-sm text-[#666] mb-8">Provide read-only AWS credentials to establish a scanning session.</p>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
            <div>
              <div className="text-[10px] font-semibold uppercase tracking-[0.15em] text-[#444] mb-4">AWS Console Steps</div>
              <div className="space-y-4">
                <StepGuide num="01" text='In the AWS IAM console, go to Policies → Create Policy. Switch to JSON mode and paste the document on the right. This grants BreakBot read-only access to scan your resources.' />
                <StepGuide num="02" text='Go to IAM → Users → Create User. Skip console access, attach the policy you just created, then navigate to Security Credentials and generate an Access Key.' />
                <StepGuide num="03" text='Copy the Access Key ID and Secret Access Key from IAM and paste them into the form below. BreakBot will use these to establish a read-only scanning session.' />
              </div>
            </div>
            <div className="border border-[#1e1e2e] bg-[#0e0e16] rounded overflow-hidden">
              <div className="flex items-center justify-between px-4 py-2 border-b border-[#222]">
                <span className="text-xs text-[#555]">SecurityAudit Policy Document</span>
                <button onClick={handleCopyPolicy} className="px-3 py-1 text-xs border border-[#333] text-[#999] rounded hover:text-white hover:border-[#555] transition">
                  {copied ? 'Copied' : 'Copy JSON'}
                </button>
              </div>
              <pre className="p-4 text-xs overflow-auto max-h-56 font-mono leading-relaxed">
                {POLICY_JSON.split('\n').map((line, i) => {
                  const keyMatch = line.match(/^(\s*)"([^"]+)"(\s*:\s*)(.*)$/)
                  const strVal = line.match(/^(\s*)(".*")(\s*,?)$/)
                  if (keyMatch) {
                    const [, indent, key, colon, rest] = keyMatch
                    return (
                      <span key={i} className="block">
                        {indent}<span className="text-[#818cf8]">"{key}"</span><span className="text-[#4b5563]">{colon}</span><span className="text-[#4ade80]">{rest}</span>
                      </span>
                    )
                  }
                  if (strVal) {
                    const [, indent, val, comma] = strVal
                    return (
                      <span key={i} className="block">
                        {indent}<span className="text-[#fbbf24]">{val}</span><span className="text-[#6b7280]">{comma}</span>
                      </span>
                    )
                  }
                  return <span key={i} className="block text-[#6b7280]">{line}</span>
                })}
              </pre>
            </div>
          </div>

          {/* Auth tabs */}
          <div className="border-b border-[#222] mb-6">
            <div className="flex">
              <button onClick={() => setAuthMode('keys')} className={`px-4 py-2.5 text-sm border-b-2 transition ${authMode === 'keys' ? 'border-[#3b82f6] text-[#60a5fa]' : 'border-transparent text-[#555] hover:text-[#999]'}`}>
                Direct Access Keys
              </button>
              <button onClick={() => setAuthMode('profile')} className={`px-4 py-2.5 text-sm border-b-2 transition ${authMode === 'profile' ? 'border-[#3b82f6] text-[#60a5fa]' : 'border-transparent text-[#555] hover:text-[#999]'}`}>
                Local Dev Session (boto3 Profile)
              </button>
            </div>
          </div>

          {authMode === 'keys' ? (
            <div className="border border-[#1e1e2e] bg-[#0e0e16] rounded p-5 mb-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                <div>
                  <label className="text-[10px] font-semibold uppercase tracking-[0.15em] text-[#555] mb-2 block">AWS Access Key ID</label>
                  <input value={accessKey} onChange={(e) => setAccessKey(e.target.value)}
                    className="w-full bg-[#111111] border border-[#2a2a2a] rounded px-3 py-2.5 text-sm text-white font-mono outline-none focus:border-[#444] transition" placeholder="AKIA..." />
                </div>
                <div>
                  <label className="text-[10px] font-semibold uppercase tracking-[0.15em] text-[#555] mb-2 block">AWS Secret Access Key</label>
                  <input type="password" value={secretKey} onChange={(e) => setSecretKey(e.target.value)}
                    className="w-full bg-[#111111] border border-[#2a2a2a] rounded px-3 py-2.5 text-sm text-white font-mono outline-none focus:border-[#444] transition" placeholder="••••••••" />
                </div>
              </div>
              <div className="max-w-xs">
                <label className="text-[10px] font-semibold uppercase tracking-[0.15em] text-[#555] mb-2 block">Default Region</label>
                <input value={region} onChange={(e) => setRegion(e.target.value)}
                  className="w-full bg-[#111111] border border-[#2a2a2a] rounded px-3 py-2.5 text-sm text-white font-mono outline-none focus:border-[#444] transition" />
              </div>
            </div>
          ) : (
            <div className="border border-[#1e1e2e] bg-[#0e0e16] rounded p-5 mb-6">
              <p className="text-sm text-[#666] mb-4">
                Uses credentials from <span className="font-mono text-[#999]">~/.aws/credentials</span>. No keys required.
              </p>
              <div className="flex items-center gap-4">
                <label className="text-[10px] font-semibold uppercase tracking-[0.15em] text-[#555]">Profile:</label>
                <input value={profile} onChange={(e) => setProfile(e.target.value)}
                  className="bg-[#111111] border border-[#2a2a2a] rounded px-3 py-2 text-sm text-white font-mono outline-none focus:border-[#444] w-48" />
              </div>
            </div>
          )}

          <div className="flex items-center justify-between mb-8">
            <a href="/" className="text-sm text-[#555] hover:text-[#999] transition">← Cancel</a>
            <button onClick={handleConnect} disabled={validating || connectionVerified}
              className="px-5 py-2.5 bg-[#2563eb] text-white text-sm font-semibold rounded hover:bg-[#1d4ed8] transition disabled:opacity-40 disabled:cursor-not-allowed">
              {validating ? 'Connecting...' : connectionVerified ? 'Connected' : 'Connect to AWS Session'}
            </button>
          </div>

          {handshakeLogs.length > 0 && (
            <div className="border border-[#1e1e2e] bg-[#0e0e16] rounded overflow-hidden">
              <div className="px-4 py-2 border-b border-[#222]">
                <span className="text-[10px] font-semibold uppercase tracking-[0.15em] text-[#444]">Real-time Handshake Logs</span>
              </div>
              <div className="p-4 space-y-2">
                {handshakeLogs.map((log, i) => (
                  <div key={i} className="flex items-start gap-2 text-sm">
                    <span className={`${log.color} font-bold shrink-0`}>{log.icon}</span>
                    <span className="text-[#aaa]">{log.text}</span>
                  </div>
                ))}
              </div>
              {connectionVerified && (
                <div className="px-4 py-3 border-t border-[#166534]/30 bg-[#14532d]/20 flex items-center justify-between">
                  <span className="text-sm text-[#4ade80]">Connection verified — account {discovery?.account_id}</span>
                  <button onClick={() => setStep('verify')}
                    className="px-4 py-2 bg-[#2563eb] text-white text-xs font-semibold rounded hover:bg-[#1d4ed8] transition">
                    Configure Scopes
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ═══════════════ Step 2: Verify ═══════════════ */}
      {step === 'verify' && discovery && (
        <div>
          <h1 className="text-xl font-semibold text-white mb-1">Account Verified</h1>
          <p className="text-sm text-[#666] mb-6">Credentials authenticated. Environment detection complete.</p>

          <div className="border border-[#1e1e2e] bg-[#0e0e16] rounded overflow-hidden mb-5">
            <div className="flex items-center gap-2 px-4 py-2.5 border-b border-[#1e1e2e]">
              <span className="w-1.5 h-1.5 rounded-full bg-[#4ade80]" />
              <span className="text-[10px] font-semibold uppercase tracking-[0.15em] text-[#4b5563]">Environment Auto-Detected</span>
              <span className="ml-auto text-xs text-[#6b7280] font-mono">Verified {discovery.account_id}</span>
            </div>
            <div className="p-5 space-y-3 font-mono text-sm">
              <div className="flex items-start gap-3">
                <span className="text-[#4b5563] shrink-0 w-44">STS Principal ID:</span>
                <span className="text-[#4ade80]">arn:aws:iam::{discovery.account_id}:user/breakbot-scanner</span>
              </div>
              <div className="flex items-start gap-3">
                <span className="text-[#4b5563] shrink-0 w-44">Organizations Access:</span>
                <span className={discovery.is_org ? 'text-[#818cf8]' : 'text-[#f87171]'}>
                  {discovery.is_org ? 'Organization — multi-account mode' : 'AccessDenied (Standalone account node)'}
                </span>
              </div>
              <div className="flex items-start gap-3">
                <span className="text-[#4b5563] shrink-0 w-44">CloudTrail Tracking:</span>
                <span className="text-[#fbbf24]">
                  {discovery.org_trail_accessible ? 'Org trail accessible' : 'LookupEvents API endpoints active'}
                </span>
              </div>
              <div className="flex items-start gap-3">
                <span className="text-[#4b5563] shrink-0 w-44">Executing Scopes:</span>
                <span className="text-[#4ade80]">
                  {discovery.is_org ? 'Multi-account audit verified' : 'Single Account audit verified'}
                </span>
              </div>
            </div>
          </div>

          <div className="flex items-center justify-between">
            <button onClick={() => setStep('connect')} className="text-sm text-[#555] hover:text-[#999] transition">← Back</button>
            <button onClick={() => setStep('configure')}
              className="px-5 py-2.5 bg-[#2563eb] text-white text-sm font-semibold rounded hover:bg-[#1d4ed8] transition">
              Configure Scan
            </button>
          </div>
        </div>
      )}

      {/* ═══════════════ Step 3: Configure ═══════════════ */}
      {step === 'configure' && (
        <div>
          <h1 className="text-xl font-semibold text-white mb-1">Scan Configuration</h1>
          <p className="text-sm text-[#666] mb-6">Select target regions and CloudTrail lookback settings.</p>

          <div className="border border-[#1e1e2e] bg-[#0e0e16] rounded p-5 mb-5">
            <div className="flex items-center justify-between mb-4">
              <span className="text-[10px] font-semibold uppercase tracking-[0.15em] text-[#555]">Audit Target Regions</span>
              <div className="flex gap-2">
                <button onClick={() => setSelectedRegions(REGION_LIST.map(r => r.code))}
                  className="px-3 py-1 text-xs border border-[#2a2a2a] text-[#666] rounded hover:text-white hover:border-[#444] transition">Select All</button>
                <button onClick={() => setSelectedRegions([region])}
                  className="px-3 py-1 text-xs border border-[#2a2a2a] text-[#666] rounded hover:text-white hover:border-[#444] transition">Reset</button>
              </div>
            </div>

            <div className="relative mb-4" onClick={e => e.stopPropagation()}>
              <div className="flex items-center bg-[#111111] border border-[#2a2a2a] rounded px-3 py-2.5 gap-2 focus-within:border-[#444]">
                <span className="text-[#444] text-xs shrink-0">↗</span>
                <input
                  value={regionSearch}
                  onChange={e => { setRegionSearch(e.target.value); setRegionDropdownOpen(true) }}
                  onFocus={() => setRegionDropdownOpen(true)}
                  placeholder="Search and select AWS regions..."
                  className="bg-transparent outline-none text-white text-sm w-full placeholder:text-[#444]"
                />
                <button onClick={() => setRegionDropdownOpen(o => !o)} className="text-[#444] text-xs shrink-0 px-1 py-0.5 hover:text-[#999] transition">
                  {regionDropdownOpen ? '▲' : '▼'}
                </button>
              </div>

              {regionDropdownOpen && (
                <div className="absolute z-10 w-full mt-1 bg-[#161616] border border-[#2a2a2a] rounded overflow-hidden shadow-2xl max-h-56 overflow-y-auto">
                  {filteredRegions.map(r => {
                    const selected = selectedRegions.includes(r.code)
                    return (
                      <button
                        key={r.code}
                        onClick={() => toggleRegion(r.code)}
                        className={`w-full flex items-center justify-between px-4 py-2 text-left hover:bg-[#1c1c1c] transition border-b border-[#1c1c1c] last:border-0 ${selected ? 'bg-[#1c1c1c]' : ''}`}
                      >
                        <div className="flex items-center gap-6 flex-1 min-w-0">
                          <span className={`text-sm font-mono shrink-0 w-36 ${selected ? 'text-white' : 'text-[#aaa]'}`}>{r.code}</span>
                          <span className="text-xs text-[#555] truncate">{r.name}</span>
                        </div>
                        <div className={`w-4 h-4 rounded border flex items-center justify-center shrink-0 ml-4 transition ${selected ? 'bg-[#2563eb] border-[#2563eb]' : 'border-[#333]'}`}>
                          {selected && <span className="text-white text-[10px] font-black">✓</span>}
                        </div>
                      </button>
                    )
                  })}
                </div>
              )}
            </div>

            <div>
              <div className="text-[10px] font-semibold uppercase tracking-[0.15em] text-[#444] mb-2">Active Region Scopes:</div>
              <div className="flex flex-wrap gap-1.5">
                {selectedRegions.map(r => (
                  <span key={r} className="inline-flex items-center gap-1 px-2 py-1 bg-[#78350f]/20 border border-[#92400e]/40 rounded text-xs text-[#fbbf24]">
                    {r}
                    <button onClick={() => toggleRegion(r)} className="hover:text-white ml-0.5 text-[#555]">×</button>
                  </span>
                ))}
              </div>
            </div>
          </div>

          <div className="border border-[#1e1e2e] bg-[#0e0e16] rounded p-5 mb-6">
            <div className="flex items-center gap-3 mb-4">
              <input type="checkbox" checked={trailEnabled} onChange={(e) => setTrailEnabled(e.target.checked)} className="w-4 h-4 accent-white" />
              <div>
                <span className="text-sm font-medium text-white">CloudTrail Behavioral Evidence</span>
                <span className="block text-xs text-[#555]">Overlay real API activity onto the attack graph</span>
              </div>
            </div>

            {trailEnabled && (
              <div className="ml-7 space-y-4">
                <div className="flex gap-2">
                  {(['fast', 'deep', 'custom'] as const).map((m) => (
                    <button key={m} onClick={() => setTrailMode(m)}
                      className={`px-3 py-1.5 text-xs rounded transition ${trailMode === m ? 'bg-[#1e3a5f] border border-[#3b82f6]/50 text-[#93c5fd]' : 'border border-[#1e1e2e] text-[#555] hover:text-[#999]'}`}>
                      {m === 'fast' ? 'Fast — 14d / 20pg' : m === 'deep' ? 'Deep — 90d / 100pg' : 'Custom'}
                    </button>
                  ))}
                </div>
                {trailMode === 'custom' && (
                  <div className="grid grid-cols-2 gap-4 border border-[#1e1e2e] bg-[#0f0f0f] rounded p-4">
                    <div>
                      <label className="text-[10px] font-semibold uppercase tracking-[0.15em] text-[#555] mb-1 block">Lookback Days</label>
                      <input type="number" value={customDays} onChange={(e) => setCustomDays(Number(e.target.value))}
                        className="w-full bg-[#0e0e16] border border-[#2a2a2a] rounded px-3 py-2 text-sm text-white font-mono outline-none focus:border-[#444]" />
                    </div>
                    <div>
                      <label className="text-[10px] font-semibold uppercase tracking-[0.15em] text-[#555] mb-1 block">Max Pages / Region</label>
                      <input type="number" value={customPages} onChange={(e) => setCustomPages(Number(e.target.value))}
                        className="w-full bg-[#0e0e16] border border-[#2a2a2a] rounded px-3 py-2 text-sm text-white font-mono outline-none focus:border-[#444]" />
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

          <div className="flex items-center justify-between">
            <button onClick={() => setStep('verify')} className="text-sm text-[#555] hover:text-[#999] transition">← Back</button>
            <button onClick={handleStartScan}
              className="px-5 py-2.5 bg-[#2563eb] text-white text-sm font-semibold rounded hover:bg-[#1d4ed8] transition">
              Execute Scan
            </button>
          </div>
        </div>
      )}

      {/* ═══════════════ Step 4: Scan ═══════════════ */}
      {step === 'scan' && (
        <div>
          <div className="text-[10px] font-semibold uppercase tracking-[0.15em] text-[#555] mb-1">Executable Scanning Phase</div>
          <h1 className="text-xl font-semibold text-white font-mono mb-1">{scanId}</h1>
          <p className="text-sm text-[#555] mb-6">Collecting resources across regions: {selectedRegions.join(', ')}</p>

          <div className="flex items-center justify-between mb-1.5">
            <span className="text-xs text-[#777]">Domain Audit Mapping</span>
            <span className="text-xs font-mono text-[#aaa]">{progress}%</span>
          </div>
          <div className="w-full h-1 bg-[#1c1c1c] rounded-full overflow-hidden mb-8">
            <div className="h-full bg-[#3b82f6] rounded-full transition-all duration-500" style={{ width: `${progress}%` }} />
          </div>

          <div className="border border-[#1e1e2e] bg-[#0e0e16] rounded p-5 mb-5">
            <div className="text-[10px] font-semibold uppercase tracking-[0.15em] text-[#444] mb-4">Scanners Stack Progress</div>
            <div className="space-y-2">
              {domainProgress.map((d) => (
                <div key={d.domain} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className={`text-xs ${d.done ? 'text-[#818cf8]' : 'text-[#374151]'}`}>●</span>
                    <span className="text-sm text-[#d1d5db]">{DOMAIN_LABELS[d.domain] || d.domain}</span>
                  </div>
                  <span className={`text-xs font-mono ${d.done ? 'text-[#818cf8]' : 'text-[#4b5563]'}`}>
                    {d.done ? `Mapped ${d.count} assets` : `Scanning...`}
                  </span>
                </div>
              ))}
              {domainProgress.length === 0 && (
                <div className="text-sm text-[#444]">Initializing scanner pipeline...</div>
              )}
            </div>
          </div>

          <div className="border border-[#1e1e2e] bg-[#0e0e16] rounded overflow-hidden mb-6">
            <div className="px-4 py-2 border-b border-[#222]">
              <span className="text-[10px] font-semibold uppercase tracking-[0.15em] text-[#444]">Console Stream Out</span>
            </div>
            <div className="p-4 h-56 overflow-y-auto font-mono text-xs space-y-0.5">
              {logs.map((log, i) => (
                <div key={i} className={`${
                  log.includes('ERROR') || log.includes('FATAL') ? 'text-red-400' :
                  log.includes('assets') || log.includes('complete') || log.includes('saved') ? 'text-[#4ade80]' :
                  log.includes('[info]') ? 'text-[#555]' :
                  log.match(/^\[(\w+)\]/) ? 'text-[#aaa]' :
                  'text-[#666]'
                }`}>
                  {log}
                </div>
              ))}
              <div ref={logEndRef} />
            </div>
          </div>

          {progress === 100 && scanId && (
            <div className="flex gap-3">
              <button onClick={() => navigate(`/results/${scanId}`)}
                className="px-5 py-2.5 bg-[#2563eb] text-white text-sm font-semibold rounded hover:bg-[#1d4ed8] transition">
                View Report
              </button>
              <button onClick={() => navigate(`/graph/${scanId}`)}
                className="px-5 py-2.5 border border-[#2a2a2a] text-[#aaa] text-sm font-semibold rounded hover:text-white hover:border-[#444] transition">
                View Graph
              </button>
            </div>
          )}
        </div>
      )}
    </Layout>
  )
}

function StepGuide({ num, text }: { num: string; text: string }) {
  return (
    <div className="flex gap-3">
      <span className="text-xs font-mono text-[#444] shrink-0 mt-0.5">{num}</span>
      <p className="text-sm text-[#999] leading-relaxed">{text}</p>
    </div>
  )
}

function DetRow({ label, value, mono }: { label: string; value: string; mono?: boolean; highlight?: string }) {
  return (
    <div className="flex items-start justify-between gap-4 border-t border-[#1e1e2e] pt-3 first:border-0 first:pt-0">
      <span className="text-sm text-[#555] shrink-0">{label}</span>
      <span className={`text-sm text-[#ccc] text-right ${mono ? 'font-mono' : ''}`}>{value}</span>
    </div>
  )
}
