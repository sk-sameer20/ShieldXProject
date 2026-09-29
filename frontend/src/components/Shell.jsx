import { useState } from "react";
import { NavLink, Outlet, useLocation } from "@/lib/rr";
import { Activity, Boxes, Check, LayoutDashboard, Moon, Radar, ShieldAlert, Sun } from "lucide-react";
import { GlassButton, GlassLink, Segmented } from "@/components/Glass";
import { Mark } from "@/components/Mark";
import { useTheme } from "@/components/theme";
import { dataMode } from "@/data/telemetry";

/*
 * Detectors is intentionally absent: its content now lives on the Hero page.
 * The route below stays registered and titled, because Overview and Hero both
 * link to it — removing it would break those links.
 */
const nav = [
  { to: "/console", end: true, label: "Overview", icon: LayoutDashboard },
  { to: "/console/incidents", label: "Incidents", icon: ShieldAlert },
  { to: "/console/traffic", label: "Live traffic", icon: Activity },
  { to: "/console/system", label: "System", icon: Boxes },
];

const titles = {
  "/console": "Overview",
  "/console/incidents": "Incidents",
  "/console/traffic": "Live traffic",
  "/console/detectors": "Detectors",
  "/console/system": "System",
};

export function ThemeToggle({ size }) {
  const { theme, toggle } = useTheme();
  return (
    <GlassButton
      variant="quiet"
      size={size}
      icon
      onClick={toggle}
      aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
      title={theme === "dark" ? "Light theme" : "Dark theme"}
    >
      {theme === "dark" ? <Sun size={15} /> : <Moon size={15} />}
    </GlassButton>
  );
}

import { useShieldXWebSocketSync, useHealth } from "@/hooks/useShieldX";

export function Shell() {
  const { pathname } = useLocation();
  const [range, setRange] = useState("3h");
  const { wsStatus } = useShieldXWebSocketSync();
  const { data: health, isError } = useHealth();

  const isLive = !isError && health && wsStatus === "OPEN";
  const isConnecting = !isError && (wsStatus === "CONNECTING" || wsStatus === "RECONNECTING");
  const isOffline = isError || (!health && wsStatus === "CLOSED");

  return (
    <div className="app">
      <aside className="side">
        <GlassLink to="/" variant="quiet" className="side__brand" aria-label="ShieldX home">
          <Mark size={22} />
          <span className="side__brandtext">
            <strong>ShieldX</strong>
            <em>Passive detection</em>
          </span>
        </GlassLink>

        <nav className="side__nav" aria-label="Console sections">
          {nav.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) => `navlink ${isActive ? "navlink--on" : ""}`}
            >
              <item.icon size={15} strokeWidth={1.9} aria-hidden />
              <span>{item.label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="side__foot">
          {/* States what SHIELDX actually is, rather than implying a fleet of
              managed sensors it does not have. */}
          <div className="arch">
            <span className="arch__head">
              <i className="dot live" style={{ background: isLive ? "var(--ok)" : isConnecting ? "#eab308" : "#71717a" }} aria-hidden />
              <span className="eyebrow">{isLive ? "Passive mode" : isConnecting ? "Connecting" : "Offline"}</span>
            </span>
            <ul className="arch__list">
              {["Receive-only observation", "No return path", "No control path"].map((line) => (
                <li key={line}>
                  <Check size={12} strokeWidth={2.6} aria-hidden />
                  {line}
                </li>
              ))}
            </ul>
          </div>
          <div className="side__bottom">
            <span className="mono side__ver">v1.0</span>
            <ThemeToggle size="sm" />
          </div>
        </div>
      </aside>

      <div className="main">
        <header className="topbar glass-panel">
          <div className="topbar__left">
            {isLive ? (
              <span className="topbar__live">
                <i className="dot live" style={{ background: "var(--ok)" }} aria-hidden />
                Live
              </span>
            ) : isConnecting ? (
              <span className="topbar__live" style={{ color: "#eab308", borderColor: "rgba(234,179,8,0.2)" }}>
                <i className="dot" style={{ background: "#eab308" }} aria-hidden />
                Connecting
              </span>
            ) : (
              <span className="topbar__live" style={{ color: "var(--muted)", borderColor: "rgba(255,255,255,0.1)" }}>
                <i className="dot" style={{ background: "#71717a" }} aria-hidden />
                Offline
              </span>
            )}
            <h1 className="topbar__title">{titles[pathname] ?? "Console"}</h1>
          </div>
          <div className="topbar__right">
            <Segmented
              ariaLabel="Time range"
              value={range}
              onChange={setRange}
              options={[
                { value: "1h", label: "1h" },
                { value: "3h", label: "3h" },
                { value: "24h", label: "24h" },
              ]}
            />
          </div>
        </header>

        <main className="content" key={pathname}>
          <Outlet context={{ range }} />
        </main>
      </div>
    </div>
  );
}
