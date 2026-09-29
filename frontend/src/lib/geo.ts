/**
 * Honest GeoIP and Network Endpoint Mapping for ShieldX
 * Resolves source & destination IP endpoints to geographic coordinates.
 * Transparently indicates resolution status (Internal Enclave, Subnet Resolved, or Passive Estimated).
 */

export interface GeoEndpoint {
  ip: string;
  name: string;
  region: string;
  countryCode: string;
  lat: number;
  lon: number;
  x: number; // SVG pixel coordinate [0..1000]
  y: number; // SVG pixel coordinate [0..500]
  isInternal: boolean;
  resolutionStatus: "Internal Enclave" | "Subnet Resolved" | "Passive Estimated";
  asnOrNote: string;
}

/**
 * Projects (lat, lon) to equirectangular SVG coordinate space [1000 x 500]
 */
export function latLonToXY(lat: number, lon: number): { x: number; y: number } {
  const clampedLon = Math.max(-180, Math.min(180, lon));
  const clampedLat = Math.max(-90, Math.min(90, lat));
  const x = Math.round(((clampedLon + 180) * (1000 / 360)) * 10) / 10;
  const y = Math.round(((90 - clampedLat) * (500 / 180)) * 10) / 10;
  return { x, y };
}

/**
 * Deterministic fallback for unknown public subnets to provide realistic
 * geographic hub placement while honestly flagging it as "Passive Estimated".
 */
const GLOBAL_HUBS = [
  { name: "US East Hub", region: "North America", countryCode: "US", lat: 39.0, lon: -77.1, asn: "Transatlantic Transit" },
  { name: "Western Europe Hub", region: "Europe", countryCode: "NL", lat: 52.3, lon: 4.9, asn: "AMS-IX Exchange" },
  { name: "Central Europe Hub", region: "Europe", countryCode: "DE", lat: 50.1, lon: 8.6, asn: "DE-CIX Transit" },
  { name: "East Asia Hub", region: "Asia-Pacific", countryCode: "JP", lat: 35.6, lon: 139.7, asn: "APNIC Gateway" },
  { name: "Singapore Hub", region: "Asia-Pacific", countryCode: "SG", lat: 1.3, lon: 103.8, asn: "Equinix SG" },
  { name: "South America Hub", region: "South America", countryCode: "BR", lat: -23.5, lon: -46.6, asn: "PTT-Metro SP" },
];

function hashIpToHub(ip: string) {
  let hash = 0;
  for (let i = 0; i < ip.length; i++) {
    hash = (hash << 5) - hash + ip.charCodeAt(i);
    hash |= 0;
  }
  const index = Math.abs(hash) % GLOBAL_HUBS.length;
  return GLOBAL_HUBS[index];
}

/**
 * Resolves an IP address to geographic coordinates and metadata
 */
export function resolveGeoEndpoint(ip: string | undefined): GeoEndpoint {
  const cleanIp = (ip || "10.240.0.1").trim();

  // 1. Private RFC 1918 Enclave Sensor Networks (ShieldX Protected Enclave)
  if (
    cleanIp.startsWith("10.") ||
    cleanIp.startsWith("192.168.") ||
    cleanIp.startsWith("172.16.") ||
    cleanIp.startsWith("172.17.") ||
    cleanIp.startsWith("172.18.") ||
    cleanIp.startsWith("172.19.") ||
    cleanIp.startsWith("172.20.") ||
    cleanIp.startsWith("172.31.")
  ) {
    // Protected sensor enclave in South Asia (India Command Center)
    const { x, y } = latLonToXY(20.59, 78.96);
    return {
      ip: cleanIp,
      name: "ShieldX Defense Enclave",
      region: "Protected Enclave (IN)",
      countryCode: "IN",
      lat: 20.59,
      lon: 78.96,
      x,
      y,
      isInternal: true,
      resolutionStatus: "Internal Enclave",
      asnOrNote: "RFC1918 Enclave Sensor Node",
    };
  }

  // 2. Real telemetry subnets from ShieldX dataset & CTU-13 / Lab testnets
  // CTU-13 Dataset (Czech Technical University, Prague)
  if (cleanIp.startsWith("147.32.")) {
    const { x, y } = latLonToXY(50.08, 14.43);
    return {
      ip: cleanIp,
      name: "Prague (CTU-13 Lab)",
      region: "Central Europe",
      countryCode: "CZ",
      lat: 50.08,
      lon: 14.43,
      x,
      y,
      isInternal: false,
      resolutionStatus: "Subnet Resolved",
      asnOrNote: "AS2860 CESNET",
    };
  }

  // RFC 5737 TEST-NET-2 (Simulated North American Attacker Origin in Dataset)
  if (cleanIp.startsWith("198.51.100.")) {
    const { x, y } = latLonToXY(38.9, -77.03);
    return {
      ip: cleanIp,
      name: "North America (Testnet-2)",
      region: "North America",
      countryCode: "US",
      lat: 38.9,
      lon: -77.03,
      x,
      y,
      isInternal: false,
      resolutionStatus: "Subnet Resolved",
      asnOrNote: "RFC5737 Test Range / US East",
    };
  }

  // RFC 5737 TEST-NET-3 (APNIC / Tokyo Lab Range in Dataset)
  if (cleanIp.startsWith("203.0.113.")) {
    const { x, y } = latLonToXY(35.68, 139.76);
    return {
      ip: cleanIp,
      name: "Tokyo (Testnet-3 / C2)",
      region: "Asia-Pacific",
      countryCode: "JP",
      lat: 35.68,
      lon: 139.76,
      x,
      y,
      isInternal: false,
      resolutionStatus: "Subnet Resolved",
      asnOrNote: "RFC5737 APNIC Test Range",
    };
  }

  // Known European ASN 13335 / RIPE ranges
  if (cleanIp.startsWith("185.199.")) {
    const { x, y } = latLonToXY(52.37, 4.89);
    return {
      ip: cleanIp,
      name: "Amsterdam / RIPE",
      region: "Western Europe",
      countryCode: "NL",
      lat: 52.37,
      lon: 4.89,
      x,
      y,
      isInternal: false,
      resolutionStatus: "Subnet Resolved",
      asnOrNote: "AS13335 Cloudflare / Fastly CDN",
    };
  }

  // Known German Datacenter / Scanning range
  if (cleanIp.startsWith("92.38.")) {
    const { x, y } = latLonToXY(50.11, 8.68);
    return {
      ip: cleanIp,
      name: "Frankfurt / Datacenter",
      region: "Europe",
      countryCode: "DE",
      lat: 50.11,
      lon: 8.68,
      x,
      y,
      isInternal: false,
      resolutionStatus: "Subnet Resolved",
      asnOrNote: "AS49981 Datacenter Transit",
    };
  }

  // Eastern European Scanning Subnet
  if (cleanIp.startsWith("45.132.")) {
    const { x, y } = latLonToXY(44.43, 26.1);
    return {
      ip: cleanIp,
      name: "Bucharest / East Europe",
      region: "Eastern Europe",
      countryCode: "RO",
      lat: 44.43,
      lon: 26.1,
      x,
      y,
      isInternal: false,
      resolutionStatus: "Subnet Resolved",
      asnOrNote: "AS208044 HostRoyale",
    };
  }

  // Public DNS Anycast
  if (cleanIp === "8.8.8.8" || cleanIp === "8.8.4.4") {
    const { x, y } = latLonToXY(37.42, -122.08);
    return {
      ip: cleanIp,
      name: "Google DNS Anycast",
      region: "North America",
      countryCode: "US",
      lat: 37.42,
      lon: -122.08,
      x,
      y,
      isInternal: false,
      resolutionStatus: "Subnet Resolved",
      asnOrNote: "AS15169 Google LLC",
    };
  }

  if (cleanIp === "1.1.1.1" || cleanIp === "1.0.0.1") {
    const { x, y } = latLonToXY(37.77, -122.42);
    return {
      ip: cleanIp,
      name: "Cloudflare Anycast",
      region: "North America",
      countryCode: "US",
      lat: 37.77,
      lon: -122.42,
      x,
      y,
      isInternal: false,
      resolutionStatus: "Subnet Resolved",
      asnOrNote: "AS13335 Cloudflare",
    };
  }

  // 3. Fallback: Deterministic Hub placement flagged as "Passive Estimated"
  const hub = hashIpToHub(cleanIp);
  const { x, y } = latLonToXY(hub.lat, hub.lon);
  return {
    ip: cleanIp,
    name: `${hub.name} (Est)`,
    region: hub.region,
    countryCode: hub.countryCode,
    lat: hub.lat,
    lon: hub.lon,
    x,
    y,
    isInternal: false,
    resolutionStatus: "Passive Estimated",
    asnOrNote: `${hub.asn} [Subnet Unregistered]`,
  };
}

/**
 * Computes an arched Bezier flight path between two SVG points (x1, y1) and (x2, y2)
 */
export function computeArcTrajectory(x1: number, y1: number, x2: number, y2: number) {
  const dx = x2 - x1;
  const dy = y2 - y1;
  const dist = Math.sqrt(dx * dx + dy * dy);

  // Midpoint
  const mx = (x1 + x2) / 2;
  const my = (y1 + y2) / 2;

  // Arc altitude: proportional to distance, arched upwards (decreased y)
  // Slight lateral bow if points are vertically aligned
  const arcHeight = Math.min(130, Math.max(30, dist * 0.26));
  const cx = Math.round((mx + (y1 - y2) * 0.12) * 10) / 10;
  const cy = Math.round((my - arcHeight) * 10) / 10;

  const path = `M ${Math.round(x1 * 10) / 10} ${Math.round(y1 * 10) / 10} Q ${cx} ${cy} ${Math.round(x2 * 10) / 10} ${Math.round(y2 * 10) / 10}`;

  return {
    path,
    cx,
    cy,
    dist,
  };
}
