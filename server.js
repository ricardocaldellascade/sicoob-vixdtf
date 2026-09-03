// ============================================================================
// sicoob-vixdtf — ponte mTLS entre o Supabase da Vix DTF e a API do Sicoob.
//
// ZERO DEPENDENCIAS (so modulos nativos do Node) — de proposito: assim o
// servico roda numa imagem node pura, sem npm install, sem build.
//
// IMPORTANTE — por que nao usa fetch():
//   O fetch() do Node (undici) IGNORA a opcao `agent`. Passar um https.Agent
//   com o certificado nao funciona: o certificado nunca vai junto e o mTLS
//   falha. Por isso toda chamada ao Sicoob usa https.request(), que aceita
//   pfx/passphrase de verdade.
//
// Rotas (todas exigem o header  x-api-token: <PONTE_TOKEN>, exceto /health):
//   GET  /health                -> vivo? + variaveis faltando
//   GET  /diag                  -> testa o token no Sicoob, devolve erro CRU
//   POST /boletos               -> registra boleto
//   GET  /boletos/:nossoNumero  -> consulta boleto
//   POST /raw                   -> repassa qualquer caminho da API (testes)
// ============================================================================

import http from "node:http";
import https from "node:https";
import { URL } from "node:url";

const {
  PORT = 3000,
  PONTE_TOKEN,
  SICOOB_CLIENT_ID,
  SICOOB_CERT_P12_BASE64,
  SICOOB_CERT_PASSWORD,
  SICOOB_TOKEN_URL = "https://auth.sicoob.com.br/auth/realms/cooperado/protocol/openid-connect/token",
  SICOOB_API_BASE = "https://api.sicoob.com.br/cobranca-bancaria/v3",
  SICOOB_SCOPES = "boletos_inclusao boletos_consulta boletos_alteracao webhooks_inclusao webhooks_consulta webhooks_alteracao",
  SICOOB_NUMERO_CONTRATO,
  SICOOB_MODALIDADE = "1",
} = process.env;

const faltando = () =>
  Object.entries({ PONTE_TOKEN, SICOOB_CLIENT_ID, SICOOB_CERT_P12_BASE64, SICOOB_CERT_PASSWORD, SICOOB_NUMERO_CONTRATO })
    .filter(([, v]) => !v)
    .map(([k]) => k);

// ---------------------------------------------------------------- TLS opts
let tlsCache = null;
function tlsOpts() {
  if (tlsCache) return tlsCache;
  tlsCache = {
    pfx: Buffer.from(SICOOB_CERT_P12_BASE64, "base64"),
    passphrase: SICOOB_CERT_PASSWORD,
    minVersion: "TLSv1.2",
  };
  return tlsCache;
}

// requisicao HTTPS com certificado de cliente
function httpsReq(urlStr, { method = "GET", headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    const req = https.request(
      {
        ...tlsOpts(),
        host: u.hostname,
        port: u.port || 443,
        path: u.pathname + u.search,
        method,
        headers,
        timeout: 45000,
      },
      (res) => {
        let dados = "";
        res.on("data", (c) => (dados += c));
        res.on("end", () => {
          let json = null;
          try { json = JSON.parse(dados); } catch { /* mantem cru */ }
          resolve({ status: res.statusCode, ok: res.statusCode >= 200 && res.statusCode < 300, json, texto: dados });
        });
      }
    );
    req.on("timeout", () => req.destroy(new Error("timeout de 45s")));
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

// ------------------------------------------------------------------ token
let cache = { token: null, exp: 0 };

async function getToken(forcar = false) {
  const agora = Date.now();
  if (!forcar && cache.token && agora < cache.exp - 30000) return cache.token;

  const corpo = new URLSearchParams({
    grant_type: "client_credentials",
    client_id: SICOOB_CLIENT_ID,
    scope: SICOOB_SCOPES,
  }).toString();

  const r = await httpsReq(SICOOB_TOKEN_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "Content-Length": Buffer.byteLength(corpo),
    },
    body: corpo,
  });

  if (!r.ok || !r.json?.access_token) {
    const e = new Error("token recusado pelo Sicoob");
    e.detalhe = { httpStatus: r.status, corpo: r.json ?? r.texto.slice(0, 800) };
    throw e;
  }
  cache = { token: r.json.access_token, exp: agora + (r.json.expires_in ?? 300) * 1000 };
  return cache.token;
}

async function sicoob(metodo, caminho, corpoObj) {
  const token = await getToken();
  const corpo = corpoObj === undefined ? null : JSON.stringify(corpoObj);
  const headers = {
    Authorization: "Bearer " + token,
    client_id: SICOOB_CLIENT_ID,
    Accept: "application/json",
  };
  if (corpo) {
    headers["Content-Type"] = "application/json";
    headers["Content-Length"] = Buffer.byteLength(corpo);
  }
  const r = await httpsReq(SICOOB_API_BASE + caminho, { method: metodo, headers, body: corpo });
  return { status: r.status, ok: r.ok, body: r.json ?? r.texto.slice(0, 1500) };
}

// ------------------------------------------------------------------ server
const responder = (res, code, obj) => {
  const s = JSON.stringify(obj, null, 2);
  res.writeHead(code, { "Content-Type": "application/json; charset=utf-8" });
  res.end(s);
};

function lerCorpo(req) {
  return new Promise((resolve) => {
    let d = "";
    req.on("data", (c) => (d += c));
    req.on("end", () => { try { resolve(JSON.parse(d || "{}")); } catch { resolve({}); } });
  });
}

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, "http://x");
  const rota = u.pathname;

  if (rota === "/health") {
    return responder(res, 200, { ok: true, servico: "sicoob-vixdtf", faltandoConfig: faltando() });
  }

  // guarda
  if ((req.headers["x-api-token"] || "") !== PONTE_TOKEN) {
    return responder(res, 403, { ok: false, erro: "token invalido" });
  }

  const pend = faltando();
  if (pend.length) return responder(res, 400, { ok: false, faltandoConfig: pend });

  try {
    if (rota === "/diag" && req.method === "GET") {
      try {
        const t = await getToken(true);
        return responder(res, 200, { ok: true, tokenObtido: true, tamanho: t.length, escopos: SICOOB_SCOPES });
      } catch (e) {
        return responder(res, 400, { ok: false, erro: e.message, detalhe: e.detalhe ?? null, escoposTentados: SICOOB_SCOPES });
      }
    }

    if (rota === "/boletos" && req.method === "POST") {
      const b = await lerCorpo(req);
      const corpo = {
        numeroContrato: Number(SICOOB_NUMERO_CONTRATO),
        modalidade: Number(SICOOB_MODALIDADE),
        ...b,
      };
      const r = await sicoob("POST", "/boletos", corpo);
      return responder(res, r.ok ? 200 : r.status, { ok: r.ok, sicoob: r.body });
    }

    if (rota.startsWith("/boletos/") && req.method === "GET") {
      const nn = rota.split("/")[2];
      const qs = new URLSearchParams({
        numeroContrato: String(SICOOB_NUMERO_CONTRATO),
        modalidade: String(SICOOB_MODALIDADE),
        nossoNumero: String(nn),
      }).toString();
      const r = await sicoob("GET", "/boletos?" + qs);
      return responder(res, r.ok ? 200 : r.status, { ok: r.ok, sicoob: r.body });
    }

    // escotilha para descobrir o contrato exato da API sem republicar o servico
    if (rota === "/raw" && req.method === "POST") {
      const { metodo = "GET", caminho, corpo } = await lerCorpo(req);
      if (!caminho) return responder(res, 400, { ok: false, erro: "informe caminho" });
      const r = await sicoob(metodo, caminho, corpo);
      return responder(res, r.ok ? 200 : r.status, { ok: r.ok, sicoob: r.body });
    }

    return responder(res, 404, { ok: false, erro: "rota nao encontrada" });
  } catch (e) {
    return responder(res, 500, { ok: false, erro: e.message, detalhe: e.detalhe ?? null });
  }
});

server.listen(Number(PORT), () => {
  console.log("sicoob-vixdtf ouvindo na porta " + PORT);
  const p = faltando();
  if (p.length) console.warn("ATENCAO: variaveis faltando -> " + p.join(", "));
});
