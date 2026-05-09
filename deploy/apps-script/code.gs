const AUTH_KEY = "CHANGE_ME";

const STRIP_HEADERS = {
  host: 1, connection: 1, "content-length": 1,
  "transfer-encoding": 1, "proxy-connection": 1, "proxy-authorization": 1,
  te: 1, upgrade: 1,
  "x-forwarded-for": 1, "x-forwarded-host": 1, "x-forwarded-proto": 1,
  "x-real-ip": 1, "forwarded": 1, "via": 1,
  "accept-encoding": 1,
};

const _GAS_URL_RE = /^https?:\/\/script\.google\.com\/macros\//i;

function doPost(e) {
  try {
    const req = JSON.parse(e.postData.contents);
    if (req.k !== AUTH_KEY) return _json({ e: "unauthorized" });
    if (Array.isArray(req.q)) return _doBatch(req.q);
    return _doSingle(req);
  } catch (err) {
    return _json({ e: String(err) });
  }
}

function _doSingle(req) {
  if (!req.u || typeof req.u !== "string" || !req.u.match(/^https?:\/\//i)) {
    return _json({ e: "bad url" });
  }
  if (_GAS_URL_RE.test(req.u)) {
    return _json({ e: "loop detected" });
  }
  const opts = _buildOpts(req);
  const resp = UrlFetchApp.fetch(req.u, opts);
  return _json(_buildResult(resp));
}

function _doBatch(items) {
  const fetchArgs = [];
  const fetchIndex = [];
  const errorMap = {};

  for (let i = 0; i < items.length; i++) {
    const item = items[i];
    if (!item || typeof item !== "object") {
      errorMap[i] = "bad item";
      continue;
    }
    if (!item.u || typeof item.u !== "string" || !item.u.match(/^https?:\/\//i)) {
      errorMap[i] = "bad url";
      continue;
    }
    if (_GAS_URL_RE.test(item.u)) {
      errorMap[i] = "loop detected";
      continue;
    }
    try {
      const opts = _buildOpts(item);
      opts.url = item.u;
      fetchArgs.push(opts);
      fetchIndex.push(i);
    } catch (err) {
      errorMap[i] = String(err);
    }
  }

  let responses = [];
  if (fetchArgs.length > 0) {
    try {
      responses = UrlFetchApp.fetchAll(fetchArgs);
    } catch (err) {
      const msg = "fetchAll failed: " + String(err);
      for (let j = 0; j < fetchArgs.length; j++) {
        errorMap[fetchIndex[j]] = msg;
      }
    }
  }

  const results = [];
  let rIdx = 0;
  for (let i = 0; i < items.length; i++) {
    if (Object.prototype.hasOwnProperty.call(errorMap, i)) {
      results.push({ e: errorMap[i] });
    } else {
      const resp = responses[rIdx++];
      if (!resp) {
        results.push({ e: "fetch failed" });
      } else {
        results.push(_buildResult(resp));
      }
    }
  }
  return _json({ q: results });
}

function _buildOpts(req) {
  const opts = {
    method: (req.m || "GET").toLowerCase(),
    muteHttpExceptions: true,
    followRedirects: req.r !== false,
    validateHttpsCertificates: true,
    escaping: false,
    headers: {},
  };
  if (req.h && typeof req.h === "object") {
    for (const k in req.h) {
      if (Object.prototype.hasOwnProperty.call(req.h, k) &&
          !STRIP_HEADERS[k.toLowerCase()]) {
        opts.headers[k] = req.h[k];
      }
    }
  }
  if (req.b) {
    opts.payload = Utilities.base64Decode(req.b);
    if (req.ct) opts.contentType = req.ct;
  }
  return opts;
}

function _buildResult(resp) {
  const gz = _maybeGzip(resp.getContent());
  const out = {
    s: resp.getResponseCode(),
    h: _respHeaders(resp),
    b: Utilities.base64Encode(gz.b),
  };
  if (gz.gz) out.gz = 1;
  return out;
}

function _maybeGzip(bytes) {
  try {
    const compressed = Utilities.gzip(Utilities.newBlob(bytes)).getBytes();
    if (compressed.length < bytes.length) return { b: compressed, gz: true };
  } catch (_) {}
  return { b: bytes, gz: false };
}

function _respHeaders(resp) {
  try {
    if (typeof resp.getAllHeaders === "function") return resp.getAllHeaders();
  } catch (_) {}
  return resp.getHeaders();
}

function _json(obj) {
  return ContentService
    .createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}

function doGet() {
  return ContentService.createTextOutput("ok").setMimeType(ContentService.MimeType.TEXT);
}
