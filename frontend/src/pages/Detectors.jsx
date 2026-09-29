import { useMemo } from "react";
import { DetectorCard } from "@/components/DetectorCard";
import { SectionHead } from "@/components/ui";
import { models } from "@/data/telemetry";
import { useDetectorsStatus } from "@/hooks/useShieldX";

/*
 * Kept as a route because the Overview and Hero pages link to it, though it no
 * longer appears in the sidebar — the same cards now live on the Hero page.
 */
export function Detectors() {
  const { data: statusList, isSuccess } = useDetectorsStatus();

  const statusMap = useMemo(() => {
    const map = {};
    if (isSuccess && Array.isArray(statusList)) {
      statusList.forEach((s) => {
        const key = String(s.engine_type || "").toUpperCase().replace("-", "_");
        map[key] = s;
        map[String(s.engine_type || "").toUpperCase()] = s;
      });
    }
    return map;
  }, [statusList, isSuccess]);

  return (
    <>
      <SectionHead
        eyebrow="Models"
        title="Detectors"
        hint="Four detectors score every window independently. Each one is documented here with the features it reads and the thresholds it was configured with, so a verdict can always be traced back to a number."
      />

      <div className="stack" style={{ gap: 16 }}>
        {models.map((m) => {
          const key = m.threat_class.toUpperCase().replace("-", "_");
          const liveStatus = statusMap[key] || statusMap[m.threat_class.toUpperCase()];
          return (
            <DetectorCard
              key={m.threat_class}
              model={m}
              liveStatus={liveStatus}
              isLive={isSuccess}
            />
          );
        })}
      </div>
    </>
  );
}
