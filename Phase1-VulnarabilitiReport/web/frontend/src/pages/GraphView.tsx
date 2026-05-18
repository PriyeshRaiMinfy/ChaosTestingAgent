import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'

export default function GraphView() {
  const { scanId } = useParams()
  const navigate = useNavigate()
  const [html, setHtml] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetch(`/api/scan/${scanId}/graph`)
      .then(r => r.ok ? r.json() : Promise.reject('Graph not available'))
      .then(data => setHtml(data.html))
      .catch(() => setError('Graph not available for this scan.'))
  }, [scanId])

  if (error) {
    return (
      <div className="min-h-screen bg-[#0a0a0f] flex flex-col items-center justify-center gap-4">
        <div className="text-zinc-400">{error}</div>
        <button onClick={() => navigate(`/results/${scanId}`)} className="text-cyan-400 hover:text-cyan-300 text-sm">
          ← Back to results
        </button>
      </div>
    )
  }

  return (
    <div className="h-screen flex flex-col bg-[#0a0a0f]">
      <div className="flex items-center justify-between px-4 py-2 border-b border-white/10 bg-[#111118] shrink-0">
        <div className="flex items-center gap-4">
          <button onClick={() => navigate(`/results/${scanId}`)} className="text-zinc-400 hover:text-white text-sm transition">
            ← Results
          </button>
          <span className="text-sm text-zinc-500 font-mono">{scanId}</span>
        </div>
        {html && (
          <a
            href={URL.createObjectURL(new Blob([html], { type: 'text/html' }))}
            target="_blank"
            className="px-3 py-1 text-xs bg-[#1a1a24] border border-white/10 rounded text-zinc-300 hover:border-cyan-500/50 transition"
          >
            Open Full
          </a>
        )}
      </div>

      {html ? (
        <iframe
          srcDoc={html}
          className="flex-1 w-full border-none"
          title="Dependency Graph"
          sandbox="allow-scripts"
        />
      ) : (
        <div className="flex-1 flex items-center justify-center text-zinc-500">Loading graph...</div>
      )}
    </div>
  )
}
