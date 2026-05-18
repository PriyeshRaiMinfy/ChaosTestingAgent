import { Routes, Route } from 'react-router-dom'
import Landing from './pages/Landing'
import Wizard from './pages/Wizard'
import Results from './pages/Results'
import GraphView from './pages/GraphView'

function App() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route path="/scan" element={<Wizard />} />
      <Route path="/results/:scanId" element={<Results />} />
      <Route path="/graph/:scanId" element={<GraphView />} />
    </Routes>
  )
}

export default App
