import { createFileRoute } from "@tanstack/react-router";
import { Detectors } from "@/pages/Detectors";

export const Route = createFileRoute("/console/detectors")({
  head: () => ({
    meta: [
      { title: "Detectors — ShieldX Console" },
      { name: "description", content: "How ShieldX detects DDoS, C2 beaconing, DGA and DNS tunnelling." },
      { property: "og:title", content: "Detectors — ShieldX Console" },
      { property: "og:description", content: "How ShieldX detects DDoS, C2 beaconing, DGA and DNS tunnelling." },
    ],
  }),
  component: Detectors,
});
