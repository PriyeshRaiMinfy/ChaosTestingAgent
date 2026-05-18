import { useNavigate } from 'react-router-dom'

export default function Landing() {
  const navigate = useNavigate()

  return (
    <div className="min-h-screen bg-[#111111] text-[#e8e8e8]">
      {/* Header */}
      <header className="flex items-center justify-between px-10 py-4 border-b border-[#1e1e2e]">
        <div className="flex items-center gap-2.5">
          <span className="grid h-6 w-6 place-items-center rounded bg-[#1e1b4b] border border-[#3730a3]/40 text-[9px] font-black text-[#a5b4fc]">BB</span>
          <span className="text-sm font-semibold tracking-wide text-white">BreakBot</span>
        </div>
        <nav className="flex gap-6 text-sm text-[#6b7280]">
          <a href="#how-it-works" className="hover:text-[#d1d5db] transition-colors">How It Works</a>
          <a href="#coverage" className="hover:text-[#d1d5db] transition-colors">Coverage</a>
          <a href="https://github.com/PriyeshRaiMinfy/ChaosTestingAgent" target="_blank" className="hover:text-[#d1d5db] transition-colors">GitHub</a>
        </nav>
      </header>

      {/* Hero — left-aligned */}
      <section className="px-10 pt-20 pb-14">
        <div className="max-w-4xl">
          <div className="inline-flex items-center gap-2 px-2.5 py-1 bg-[#1e1b4b]/60 border border-[#3730a3]/30 rounded text-xs text-[#818cf8] mb-6">
            <span className="w-1.5 h-1.5 rounded-full bg-[#818cf8]" />
            Automated AWS Vulnerability Testing
          </div>
          <h1 className="text-4xl md:text-5xl font-semibold text-white mb-4 leading-tight tracking-tight">
            Automated Vulnerability Testing for Cloud Infrastructure
          </h1>
          <p className="text-base text-[#6b7280] mb-8 max-w-3xl leading-relaxed">
            With so many active services running in your cloud, finding every security gap is nearly impossible.<br />
            BreakBot automatically scans all your provisioned resources, pinpoints vulnerabilities, and suggests the exact configuration fix for each one — so your infrastructure is hardened before an attacker gets the chance.
          </p>
          <button
            onClick={() => navigate('/scan')}
            className="px-6 py-2.5 bg-[#4f46e5] text-white text-sm font-semibold rounded hover:bg-[#4338ca] transition-colors"
          >
            Start a Scan
          </button>
        </div>
      </section>

      {/* How It Works */}
      <section id="how-it-works" className="px-10 py-14 border-t border-[#1e1e2e]">
        <div className="max-w-4xl">
          <h2 className="text-lg font-bold text-[#818cf8] mb-6">How It Works</h2>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-px bg-[#1e1e2e]">
            {[
              { num: '01', title: 'Connect', desc: 'Provide read-only AWS credentials or use a local profile. BreakBot never writes to your account.' },
              { num: '02', title: 'Scan', desc: '14 domain scanners run in parallel — compute, networking, identity, data, serverless, and more.' },
              { num: '03', title: 'Graph', desc: 'Resources are linked by IAM, network, and CloudTrail behavioral edges into an attack graph.' },
              { num: '04', title: 'Exploit', desc: 'Claude traces kill chains, scores blast radius per path, and pinpoints the single control that breaks each attack.' },
            ].map((item) => (
              <div key={item.num} className="bg-[#111111] p-6">
                <div className="text-xs font-mono text-[#3730a3] mb-3">{item.num}</div>
                <h3 className="text-sm font-semibold text-white mb-2">{item.title}</h3>
                <p className="text-sm text-[#6b7280] leading-relaxed">{item.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Coverage */}
      <section id="coverage" className="px-10 py-14 border-t border-[#1e1e2e]">
        <div className="max-w-4xl">
          <h2 className="text-lg font-bold text-[#818cf8] mb-6">AWS Coverage</h2>
          <div className="flex flex-wrap gap-2">
            {[
              'EC2', 'EKS', 'Lambda', 'S3', 'RDS', 'IAM Roles', 'IAM Users',
              'VPC', 'Security Groups', 'API Gateway', 'CloudTrail', 'KMS',
              'Secrets Manager', 'DynamoDB', 'SNS', 'SQS', 'WAF', 'CloudFront',
              'Route53', 'ECS', 'ElastiCache', 'Cognito',
            ].map((s) => (
              <span key={s} className="px-2.5 py-1 bg-[#0e0e16] border border-[#1e1e2e] rounded text-xs text-[#6b7280]">
                {s}
              </span>
            ))}
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-[#1e1e2e] px-10 py-8">
        <div className="max-w-4xl flex items-center justify-between text-xs text-[#374151]">
          <span>BreakBot — Read-only AWS security analysis</span>
          <span>Built with Claude AI, FastAPI, React</span>
        </div>
      </footer>
    </div>
  )
}
