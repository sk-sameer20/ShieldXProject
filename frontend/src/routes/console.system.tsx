import { createFileRoute } from "@tanstack/react-router";
import { System } from "@/pages/System";

export const Route = createFileRoute("/console/system")({
  head: () => ({
    meta: [
      { title: "System — ShieldX Console" },
      { name: "description", content: "Receive-only architecture and pipeline state." },
      { property: "og:title", content: "System — ShieldX Console" },
      { property: "og:description", content: "Receive-only architecture and pipeline state." },
    ],
  }),
  component: System,
});
