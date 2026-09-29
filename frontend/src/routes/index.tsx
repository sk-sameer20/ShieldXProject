import { createFileRoute } from "@tanstack/react-router";
import { Landing } from "@/pages/Landing";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "ShieldX — Passive Network Threat Detection" },
      { name: "description", content: "ShieldX detects DDoS, C2 beaconing, DGA domains and DNS tunnelling from passive, receive-only network traffic." },
      { property: "og:title", content: "ShieldX — Passive Network Threat Detection" },
      { property: "og:description", content: "ShieldX detects DDoS, C2 beaconing, DGA domains and DNS tunnelling from passive, receive-only network traffic." },
    ],
  }),
  component: Landing,
});
