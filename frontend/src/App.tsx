const phaseGoals = [
  "Discover AWS resources through a read-only account integration",
  "Normalize infrastructure into a stable internal model",
  "Build dependency edges across network, compute, and data services",
  "Render an interactive infrastructure graph for operators"
];

export function App() {
  return (
    <main className="app-shell">
      <section className="hero">
        <p className="eyebrow">AWS Infrastructure Discovery & Visualization</p>
        <h1>InfraLens</h1>
        <p className="lead">
          A cloud engineering tool for turning fragmented AWS accounts into a
          navigable graph of networks, compute, databases, and exposure risks.
        </p>
      </section>

      <section className="panel">
        <h2>Phase 1 Baseline</h2>
        <p>
          This phase establishes the repository, architecture notes, and a
          frontend shell that will later consume scan and graph APIs from the Go
          backend.
        </p>
      </section>

      <section className="panel">
        <h2>Target Capabilities</h2>
        <ul>
          {phaseGoals.map((goal) => (
            <li key={goal}>{goal}</li>
          ))}
        </ul>
      </section>
    </main>
  );
}

