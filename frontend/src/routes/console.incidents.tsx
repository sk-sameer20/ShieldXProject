import { createFileRoute } from "@tanstack/react-router";
import { Incidents } from "@/pages/Incidents";

export const Route = createFileRoute("/console/incidents")({
  head: () => ({
    meta: [
      { title: "Incidents — ShieldX Console" },
      { name: "description", content: "Investigate alerts and the evidence behind every verdict." },
      { property: "og:title", content: "Incidents — ShieldX Console" },
      { property: "og:description", content: "Investigate alerts and the evidence behind every verdict." },
    ],
  }),
  component: Incidents,
});
