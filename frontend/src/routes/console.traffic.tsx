import { createFileRoute } from "@tanstack/react-router";
import { Traffic } from "@/pages/Traffic";

export const Route = createFileRoute("/console/traffic")({
  head: () => ({
    meta: [
      { title: "Live traffic — ShieldX Console" },
      { name: "description", content: "Live view of passively observed network flows." },
      { property: "og:title", content: "Live traffic — ShieldX Console" },
      { property: "og:description", content: "Live view of passively observed network flows." },
    ],
  }),
  component: Traffic,
});
