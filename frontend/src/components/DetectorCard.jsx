import { Panel, ThreatTag } from "@/components/ui";
import { config, threatMeta } from "@/data/telemetry";

/*
 * One detector's documentation card, extracted unchanged from the Detectors
 * page so the Hero page and the Detectors route render exactly the same markup
 * from one definition. No content was altered in the move.
 */

const thresholdCopy = {
  C2: config.c2,
  DGA: config.dga,
  "DNS-Tunnel": config.dns_tunnel,
};

export function DetectorCard({ model, liveStatus, isLive = true }) {
  const metaBadge = !isLive
    ? `${model.version} · Offline`
    : liveStatus?.status
      ? `${model.version} · ${liveStatus.status}`
      : `${model.version} · Configured`;

  return (
    <Panel
      title={threatMeta[model.threat_class].label}
      meta={metaBadge}
      hint={liveStatus?.rule_name ? `${threatMeta[model.threat_class].blurb} · Rule: ${liveStatus.rule_name}` : threatMeta[model.threat_class].blurb}
    >
      <div className="det">
        <dl className="det__facts">
          <div>
            <dt>Approach</dt>
            <dd>{model.kind}</dd>
          </div>
          <div>
            <dt>Trained on</dt>
            <dd>{model.trained_on}</dd>
          </div>
          <div>
            <dt>Scoring window</dt>
            <dd>{model.window}</dd>
          </div>
          {liveStatus?.cadence_or_duration && (
            <div>
              <dt>Cadence / Window</dt>
              <dd className="mono">{liveStatus.cadence_or_duration}</dd>
            </div>
          )}
        </dl>

        <div className="det__cols">
          <div>
            <p className="det__sub">
              Features it reads
              <span className="det__count tnum">{model.features.length}</span>
            </p>
            <ul className="chips">
              {model.features.map((f) => (
                <li key={f} className="chip mono">
                  {f}
                </li>
              ))}
            </ul>
          </div>

          <div>
            {thresholdCopy[model.threat_class] ? (
              <>
                <p className="det__sub">Configured thresholds</p>
                <dl className="thresh">
                  {Object.entries(thresholdCopy[model.threat_class]).map(([k, v]) => (
                    <div key={k}>
                      <dt className="mono">{k}</dt>
                      <dd className="tnum">{v}</dd>
                    </div>
                  ))}
                </dl>
              </>
            ) : (
              <>
                <p className="det__sub">How the line is set</p>
                <p className="det__learned">
                  No fixed numbers. Each link learns its own mean and variance online, and a window is flagged when it
                  sits more than eight standard deviations above that. A quiet link and a busy one get different bars
                  automatically — and once a host alerts, its baseline is frozen so the attack cannot teach the model
                  that the attack is normal.
                </p>
              </>
            )}
          </div>
        </div>

        <p className="det__note">
          <ThreatTag threat_class={model.threat_class} size="sm" />
          {model.notes}
        </p>
      </div>
    </Panel>
  );
}
