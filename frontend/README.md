# ShieldX — Network Threat Detection Console

Frontend application for the **ShieldX Cyber Defense Platform**, providing real-time telemetry visualization, tri-stage detection feeds (C2 beaconing, volumetric DDoS, algorithmic DGA/DNS anomalies), incident management, and passive sensor health monitoring.

## Tech Stack
- **Framework**: React 19 + TanStack Start (TypeScript)
- **Styling**: Tailwind CSS + Radix UI primitives + Lucide Icons
- **State & Data**: TanStack Query + WebSocket streaming
- **Visualization**: Recharts + Custom Canvas Topologies

## Getting Started

### Prerequisites
- Node.js (v18+)
- npm or bun

### Local Development
```sh
# Install dependencies
npm install

# Start the development server (runs on port 8080 by default)
npm run dev
```

### Production Build
```sh
npm run build
```
