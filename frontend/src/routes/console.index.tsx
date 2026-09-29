import { createFileRoute } from "@tanstack/react-router";
import { Overview } from "@/pages/Overview";

export const Route = createFileRoute("/console/")({
  head: () => ({
    meta: [
      { title: "Overview — ShieldX Console" },
      { name: "description", content: "Traffic, active alerts and threat distribution at a glance." },
      { property: "og:title", content: "Overview — ShieldX Console" },
      { property: "og:description", content: "Traffic, active alerts and threat distribution at a glance." },
    ],
  }),
  component: Overview,
});
