// Cloudflare Worker in front of the collector: forwards TLS / TCP facts the backend cannot see
// itself (F296 JA3, F302 client RTT; F297 is computed from F296 on the backend).
//
// Setup
//   1. Put the collector behind a Cloudflare zone (custom domain), route it to this worker.
//   2. Worker variables: ORIGIN = https://rasp-ml-collector.onrender.com
//                        EDGE_SECRET = <random>   (same value as EDGE_SECRET on Render)
//   3. Point the app's COLLECTOR_URL at the worker's domain.
//
// The backend only believes X-Ja3-Hash / X-Client-Rtt-Ms when X-Edge-Secret matches, so a
// client that sends these headers itself gains nothing. JA3 needs Bot Management (Enterprise);
// clientTcpRtt is available on every plan.
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const target = new URL(url.pathname + url.search, env.ORIGIN);
    const headers = new Headers(request.headers);
    // never forward client-supplied values for the headers we vouch for
    for (const h of ["x-edge-secret", "x-ja3-hash", "x-client-rtt-ms"]) headers.delete(h);
    headers.set("x-edge-secret", env.EDGE_SECRET);
    const cf = request.cf || {};
    if (cf.botManagement && cf.botManagement.ja3Hash) headers.set("x-ja3-hash", cf.botManagement.ja3Hash);
    if (typeof cf.clientTcpRtt === "number") headers.set("x-client-rtt-ms", String(cf.clientTcpRtt));
    return fetch(target, {
      method: request.method,
      headers,
      body: ["GET", "HEAD"].includes(request.method) ? undefined : request.body,
      redirect: "manual",
    });
  },
};
