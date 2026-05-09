const PSK = "CHANGE_ME";

const READ_LONG_POLL_MS = 25_000;
const BUFFER_CAP_BYTES  = 4 * 1024 * 1024;

const STRIP_HEADERS = new Set([
  "host", "connection", "content-length", "transfer-encoding",
  "proxy-connection", "proxy-authorization", "te", "upgrade",
  "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
  "x-real-ip", "forwarded", "via",
  "accept-encoding",
]);

const GAS_URL_RE = /^https?:\/\/script\.google\.com\/macros\//i;

export default {
  async fetch(req, env) {
    if (req.method === "GET") {
      return Response.json({ ok: true, msg: "gorelay worker alive" });
    }
    if (req.method !== "POST") {
      return Response.json({ e: "method_not_allowed" }, { status: 405 });
    }

    let body;
    try {
      body = await req.json();
    } catch (_) {
      return Response.json({ e: "bad_json" }, { status: 400 });
    }
    if (String(body?.k ?? "") !== PSK) {
      return Response.json({ e: "unauthorized" }, { status: 401 });
    }

    const path = new URL(req.url).pathname;

    if (path === "/tunnel/open") {
      return await handleTunnelOpen(env, body);
    }

    const m = path.match(/^\/tunnel\/([A-Za-z0-9_-]{8,64})\/(write|read|close)$/);
    if (m) {
      const [, sid, verb] = m;
      const id = env.TUNNEL.idFromName(sid);
      const stub = env.TUNNEL.get(id);
      const inner = new Request(req.url, {
        method: "POST",
        headers: { "x-tunnel-verb": verb, "content-type": "application/json" },
        body: JSON.stringify(body),
      });
      return stub.fetch(inner);
    }

    if (path === "/" || path === "") {
      return await handleHTTPExit(body);
    }

    return Response.json({ e: "bad_path" }, { status: 400 });
  },
};

async function handleHTTPExit(body) {
  const u = String(body.u ?? "");
  const m = String(body.m ?? "GET").toUpperCase();
  if (!/^https?:\/\//i.test(u)) {
    return Response.json({ e: "bad_url" }, { status: 400 });
  }

  if (GAS_URL_RE.test(u)) {
    return Response.json({ e: "loop: target is an Apps Script URL" }, { status: 508 });
  }

  const headers = sanitizeHeaders(body.h);
  const reqBody = (typeof body.b === "string" && body.b.length > 0)
    ? decodeBase64(body.b)
    : undefined;

  let upstream;
  try {
    upstream = await fetch(u, {
      method: m,
      headers,
      body: reqBody,
      redirect: "manual",
    });
  } catch (err) {
    return Response.json(
      { e: "fetch failed: " + (err?.message ?? String(err)) },
      { status: 502 });
  }

  const data = new Uint8Array(await upstream.arrayBuffer());
  const respHeaders = {};
  upstream.headers.forEach((value, key) => { respHeaders[key] = value; });

  return Response.json({
    s: upstream.status,
    h: respHeaders,
    b: encodeBase64(data),
  });
}

async function handleTunnelOpen(env, body) {
  const host = String(body.host ?? "");
  const port = Number(body.port ?? 0);
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
    return Response.json({ e: "bad_open_args" }, { status: 400 });
  }
  const sid = randomSid();
  const id = env.TUNNEL.idFromName(sid);
  const stub = env.TUNNEL.get(id);
  const inner = new Request("https://internal/open", {
    method: "POST",
    headers: { "x-tunnel-verb": "open", "content-type": "application/json" },
    body: JSON.stringify({ host, port }),
  });
  const r = await stub.fetch(inner);
  if (!r.ok) return r;
  return Response.json({ sid });
}

function randomSid() {
  const buf = new Uint8Array(16);
  crypto.getRandomValues(buf);
  let s = btoa(String.fromCharCode(...buf));
  return s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export class TunnelSession {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.socket = null;
    this.writer = null;
    this.rxBuffer = [];
    this.rxBytes = 0;
    this.eof = false;
    this.error = null;
    this.readWaiters = [];
  }

  async fetch(req) {
    const verb = req.headers.get("x-tunnel-verb");
    let body;
    try { body = await req.json(); } catch (_) { body = {}; }

    try {
      switch (verb) {
        case "open":  return await this.handleOpen(body);
        case "write": return await this.handleWrite(body);
        case "read":  return await this.handleRead();
        case "close": return await this.handleClose();
        default:      return Response.json({ e: "bad_verb" }, { status: 400 });
      }
    } catch (err) {
      return Response.json({ e: String(err?.message ?? err) }, { status: 500 });
    }
  }

  async handleOpen(body) {
    if (this.socket) {
      return Response.json({ e: "already_open" }, { status: 409 });
    }
    const { connect } = await import("cloudflare:sockets");
    this.socket = connect({ hostname: body.host, port: body.port });

    this.socket.closed
      .then(() => { this.eof = true; this.notifyReaders(); })
      .catch((e) => {
        this.error = String(e?.message ?? e);
        this.eof = true;
        this.notifyReaders();
      });

    this.writer = this.socket.writable.getWriter();
    this.startReadPump();
    return Response.json({ ok: true });
  }

  async startReadPump() {
    const reader = this.socket.readable.getReader();
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        if (value && value.byteLength > 0) {
          if (this.rxBytes + value.byteLength > BUFFER_CAP_BYTES) {
            this.error = "rx buffer overflow";
            this.eof = true;
            this.notifyReaders();
            try { await this.socket.close(); } catch (_) {}
            return;
          }
          this.rxBuffer.push(value);
          this.rxBytes += value.byteLength;
          this.notifyReaders();
        }
      }
    } catch (err) {
      this.error = String(err?.message ?? err);
    } finally {
      this.eof = true;
      this.notifyReaders();
    }
  }

  async handleWrite(body) {
    if (!this.writer) {
      return Response.json({ e: "not_open" }, { status: 409 });
    }
    if (this.eof) {
      return Response.json({ e: "session closed" }, { status: 410 });
    }
    const b64 = String(body?.b ?? "");
    if (!b64) return Response.json({ ok: true });
    const bytes = decodeBase64(b64);
    await this.writer.write(bytes);
    return Response.json({ ok: true });
  }

  async handleRead() {
    if (!this.socket && !this.rxBuffer.length && !this.eof) {
      return Response.json({ e: "not_open" }, { status: 409 });
    }
    if (this.rxBuffer.length > 0) {
      return this.flushRx();
    }
    if (this.eof) {
      return Response.json({ b: "", eof: true, e: this.error ?? undefined });
    }
    return await new Promise((resolve) => {
      const timer = setTimeout(() => {
        finishWaiter();
        resolve(Response.json({ b: "", eof: false }));
      }, READ_LONG_POLL_MS);

      const finishWaiter = () => {
        clearTimeout(timer);
        const i = this.readWaiters.indexOf(handler);
        if (i >= 0) this.readWaiters.splice(i, 1);
      };

      const handler = () => {
        finishWaiter();
        if (this.rxBuffer.length > 0) {
          resolve(this.flushRx());
        } else if (this.eof) {
          resolve(Response.json({ b: "", eof: true, e: this.error ?? undefined }));
        } else {
          resolve(Response.json({ b: "", eof: false }));
        }
      };
      this.readWaiters.push(handler);
    });
  }

  flushRx() {
    let total = 0;
    for (const c of this.rxBuffer) total += c.byteLength;
    const merged = new Uint8Array(total);
    let off = 0;
    for (const c of this.rxBuffer) { merged.set(c, off); off += c.byteLength; }
    this.rxBuffer = [];
    this.rxBytes = 0;
    return Response.json({
      b: encodeBase64(merged),
      eof: this.eof,
      ...(this.eof && this.error ? { e: this.error } : {}),
    });
  }

  notifyReaders() {
    const waiters = this.readWaiters;
    this.readWaiters = [];
    for (const w of waiters) {
      try { w(); } catch (_) {}
    }
  }

  async handleClose() {
    this.eof = true;
    this.notifyReaders();
    try {
      if (this.writer) {
        try { this.writer.releaseLock(); } catch (_) {}
        this.writer = null;
      }
      if (this.socket) {
        await this.socket.close();
        this.socket = null;
      }
    } catch (_) {}
    return Response.json({ ok: true });
  }
}

function sanitizeHeaders(h) {
  const out = {};
  if (!h || typeof h !== "object") return out;
  for (const [k, v] of Object.entries(h)) {
    if (!k || STRIP_HEADERS.has(k.toLowerCase())) continue;
    out[k] = String(v ?? "");
  }
  return out;
}

function decodeBase64(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function encodeBase64(bytes) {
  const chunkSize = 0x8000;
  let bin = "";
  for (let i = 0; i < bytes.length; i += chunkSize) {
    bin += String.fromCharCode.apply(null,
      bytes.subarray(i, Math.min(i + chunkSize, bytes.length)));
  }
  return btoa(bin);
}
