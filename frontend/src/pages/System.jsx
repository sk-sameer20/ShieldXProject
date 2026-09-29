import { Fragment } from "react";
import { Ban, Check } from "lucide-react";
import { Panel, SectionHead } from "@/components/ui";
import {
  componentStatusMeta,
  implementationNotes,
  pipeline,
  securityBoundary,
  systemComponents,
} from "@/data/telemetry";

import { useHealth } from "@/hooks/useShieldX";

const GROUPS = ["Ingest", "Processing", "Detection", "Delivery"];

function StatusTag({ status }) {
  const meta = componentStatusMeta[status] || { meaning: "Operating", tone: "var(--ok)", label: "Operational" };
  return (
    <span className="cstat" title={meta.meaning}>
      <i className="cstat__dot" style={{ background: meta.tone }} aria-hidden />
      {meta.label}
    </span>
  );
}

export function System() {
  const { data: health, isSuccess } = useHealth();
  const hintText = isSuccess && health
    ? `What SHIELDX is built from, and the verified enclave boundary it observes within. Status: ${health.status} · Enclave API online.`
    : "Offline · Enclave backend unreachable. Structural architecture specification.";

  return (
    <>
      <SectionHead
        eyebrow="Platform"
        title="System"
        hint={hintText}
      />

      <Panel
        title="System status"
        hint="Every component and its role. No runtime figures appear here: throughput, memory and uptime cannot be known until the console is connected, so they are not shown."
        meta={isSuccess && health ? `${systemComponents.length} components · ${health.status}` : `${systemComponents.length} components · Offline`}
        footer={
          <span className="statlegend">
            {Object.entries(componentStatusMeta).map(([key, meta]) => (
              <span key={key} className="statlegend__item">
                <i className="cstat__dot" style={{ background: meta.tone }} aria-hidden />
                <b>{meta.label}</b> {meta.meaning}
              </span>
            ))}
          </span>
        }
      >
        <div className="tablewrap">
          <table className="table">
            <thead>
              <tr>
                <th>Component</th>
                <th>Role</th>
                <th>State</th>
              </tr>
            </thead>
            <tbody>
              {GROUPS.map((group) => (
                <Fragment key={group}>
                  <tr className="grouprow">
                    <td colSpan={3}>{group}</td>
                  </tr>
                  {systemComponents
                    .filter((c) => c.group === group)
                    .map((c) => (
                      <tr key={c.name}>
                        <td className="cname">{c.name}</td>
                        <td className="ink-2">{c.role}</td>
                        <td>
                          <StatusTag status={c.status} />
                        </td>
                      </tr>
                    ))}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <Panel
        title="Security boundary"
        hint="The property that defines the platform: it can see the network, and it cannot touch it."
      >
        <div className="bnd">
          <div className="bnd__col">
            <p className="bnd__head">What SHIELDX does</p>
            <ul className="bnd__list">
              {securityBoundary.observes.map((item) => (
                <li key={item.label} className="bnd__item">
                  <span className="bnd__icon bnd__icon--yes">
                    <Check size={12} strokeWidth={2.8} aria-hidden />
                  </span>
                  <span>
                    <b>{item.label}</b>
                    <span className="bnd__detail">{item.detail}</span>
                  </span>
                </li>
              ))}
            </ul>
          </div>
          <div className="bnd__col">
            <p className="bnd__head">What it cannot do</p>
            <ul className="bnd__list">
              {securityBoundary.cannot.map((item) => (
                <li key={item.label} className="bnd__item">
                  <span className="bnd__icon bnd__icon--no">
                    <Ban size={12} strokeWidth={2.6} aria-hidden />
                  </span>
                  <span>
                    <b>{item.label}</b>
                    <span className="bnd__detail">{item.detail}</span>
                  </span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </Panel>

      <Panel
        title="Pipeline"
        hint="The path an observation takes, end to end. Each step is a separate module."
        meta={`${pipeline.length} stages`}
      >
        <ol className="chain">
          {pipeline.map((stage, i) => (
            <li key={stage.id} className="chain__step">
              <span className="chain__n tnum">{String(i + 1).padStart(2, "0")}</span>
              <span className="chain__label">{stage.label}</span>
              {i < pipeline.length - 1 && (
                <span className="chain__arrow" aria-hidden>
                  →
                </span>
              )}
            </li>
          ))}
        </ol>
      </Panel>

      <Panel title="Implementation notes" hint="Properties of the build as it currently stands.">
        <dl className="notes">
          {implementationNotes.map((note) => (
            <div key={note.label} className="notes__row">
              <dt className="notes__k">{note.label}</dt>
              <dd className="notes__v">{note.detail}</dd>
            </div>
          ))}
        </dl>
      </Panel>
    </>
  );
}
