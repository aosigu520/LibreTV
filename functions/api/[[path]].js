/**
 * LibreTV —— DpadTV 客户端 API（Cloudflare Pages Functions）
 *
 * 为什么有这个文件：
 *   本仓库是旧版 vanilla 前端，没有服务端 API。而 DpadTV（LibreTV 的 Android TV 原生客户端）
 *   不直接请求采集站，所有搜索/详情/直播都必须经服务端代理，契约见：
 *     GET  /api/status                    -> {passwordRequired, verified, version, defaultSources, defaultLiveSources, defaultSubscriptions}
 *     POST /api/auth   {"password"}       -> {"success":true} + Set-Cookie: ltv_session
 *     POST /api/search {"wd","sources"}   -> {list:[...], failures:[...]}
 *     GET  /api/detail?id=&source=        -> {episodes:[m3u8字符串...], videoInfo:{...}}
 *     GET  /api/douban?type&tag&...       -> {items:[{id,title,cover,rating}]}
 *     GET  /api/live/playlist?url=        -> {channels:[{id,name,url,logo,group,tvgId}], groups:[...]}
 *     GET  /api/source-list?url=          -> {sources:[...], liveSources:[...]}
 *     POST /api/source/test {"url"}       -> {ok:bool, count:int}
 *
 * 运行平台是 Cloudflare Pages Functions（Workers runtime）：
 *   - 没有 node:crypto / node:dns，HMAC 用 WebCrypto（crypto.subtle），SSRF 只做字面量 IP 校验
 *   - 免费版单次请求最多 50 个子请求，所以每个源只抓 1 页（上游默认 5 页会超限）
 *
 * 配置（Cloudflare Pages → Settings → Environment variables）：
 *   PASSWORD             访问密码（不设则所有接口返回 503）
 *   DEFAULT_SOURCES      JSON 数组 [{"name","url","detail?","isAdult?"}]
 *   DEFAULT_LIVE_SOURCES JSON 数组 [{"name","url","epg?"}]
 */

// ────────────────────────────── 工具 ──────────────────────────────

const SESSION_COOKIE = 'ltv_session';
const SESSION_TTL_MS = 90 * 24 * 60 * 60 * 1000; // 90 天

const UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36';

const CMS_HEADERS = { 'User-Agent': UA, Accept: 'application/json' };

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': '*',
      ...extraHeaders,
    },
  });
}

function jsonError(message, status) {
  return json({ error: message }, status);
}

const enc = new TextEncoder();
const dec = new TextDecoder();

function bytesToHex(buf) {
  const b = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
  return s;
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest('SHA-256', enc.encode(text));
  return bytesToHex(digest);
}

async function hmacHex(secret, payload) {
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(payload));
  return bytesToHex(sig);
}

// ────────────────────────────── 鉴权 ──────────────────────────────

function getPassword(env) {
  return env.PASSWORD || '';
}

async function getSecret(env) {
  if (env.PROXY_SECRET) return env.PROXY_SECRET;
  return sha256Hex(getPassword(env) + ':libretv::session-salt');
}

async function signSession(env) {
  const expiresAt = Date.now() + SESSION_TTL_MS;
  const payload = String(expiresAt);
  const token = `${payload}.${await hmacHex(await getSecret(env), payload)}`;
  return { token, expiresAt };
}

async function verifySession(env, token) {
  if (!token) return false;
  const dot = token.lastIndexOf('.');
  if (dot <= 0) return false;
  const payload = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  const expected = await hmacHex(await getSecret(env), payload);
  if (sig.length !== expected.length) return false;
  // 定长比较，避免逐字符提前返回
  let diff = 0;
  for (let i = 0; i < sig.length; i++) diff |= sig.charCodeAt(i) ^ expected.charCodeAt(i);
  if (diff !== 0) return false;
  const expiresAt = parseInt(payload, 10);
  return Number.isFinite(expiresAt) && Date.now() < expiresAt;
}

async function checkPassword(env, input) {
  const password = getPassword(env);
  if (!password) return false;
  const a = await sha256Hex(String(input ?? ''));
  const b = await sha256Hex(password);
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function cookieValue(cookieHeader, name) {
  if (!cookieHeader) return '';
  for (const c of cookieHeader.split(';')) {
    const eq = c.indexOf('=');
    if (eq === -1) continue;
    if (c.slice(0, eq).trim() === name) return decodeURIComponent(c.slice(eq + 1).trim());
  }
  return '';
}

async function isVerified(env, request) {
  return verifySession(env, cookieValue(request.headers.get('cookie'), SESSION_COOKIE));
}

/** 未配置密码 503、未登录 401；已登录返回 null */
async function guard(env, request) {
  if (!getPassword(env)) return jsonError('服务器未设置 PASSWORD 环境变量', 503);
  if (!(await isVerified(env, request))) return jsonError('未登录', 401);
  return null;
}

// ────────────────────────────── SSRF / 出网 ──────────────────────────────

const BLOCKED_HOSTS = new Set(['localhost', '127.0.0.1', '0.0.0.0', '::1', '[::1]']);

function stripBrackets(host) {
  return String(host || '').trim().replace(/^\[+|\]+$/g, '');
}

function toIPv4(ip) {
  const v = String(ip || '').replace(/^0:0:0:0:0:/i, '::');
  const dotted = /^::(?:ffff:)?(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(v);
  if (dotted) return dotted[1];
  const hex = /^::(?:ffff:)?([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(v);
  if (!hex) return null;
  const n = (((parseInt(hex[1], 16) << 16) | parseInt(hex[2], 16)) >>> 0);
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

function isPrivateIP(ip) {
  let v = stripBrackets(ip);
  v = toIPv4(v) ?? v;
  if (/^(127\.|0\.0\.0\.0$|::1$|::$|fe80:|fc|fd)/i.test(v)) return true;
  if (v.startsWith('10.') || v.startsWith('192.168.') || v.startsWith('169.254.')) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(v)) return true;
  if (v.startsWith('100.64.') || v.startsWith('192.0.0.')) return true;
  return false;
}

/** Workers 没有 node:dns，只能做字面量校验（Workers 出站本身也到不了本机回环） */
function isAllowedUrl(raw) {
  try {
    const u = new URL(raw);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
    const host = stripBrackets(u.hostname);
    if (BLOCKED_HOSTS.has(host) || BLOCKED_HOSTS.has(host.toLowerCase())) return false;
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':')) {
      if (isPrivateIP(host)) return false;
    }
    return true;
  } catch {
    return false;
  }
}

/** 带超时与手动跟随跳转的出网请求（每一跳重新做 SSRF 校验） */
async function fetchUpstream(rawUrl, options = {}) {
  const { timeoutMs = 10000, headers = {}, allowPrivate = false, retries = 0 } = options;
  let lastError = null;

  for (let attempt = 0; attempt <= retries; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      let current = rawUrl;
      let finalUrl = rawUrl;
      for (let hop = 0; hop <= 5; hop++) {
        if (!allowPrivate && !isAllowedUrl(current)) throw new Error('目标地址不在允许范围内（仅支持公网 http/https）');
        const res = await fetch(current, { headers, redirect: 'manual', signal: controller.signal });
        if ([301, 302, 303, 307, 308].includes(res.status)) {
          const loc = res.headers.get('location');
          if (!loc) return { res, finalUrl: current };
          current = new URL(loc, current).href;
          finalUrl = current;
          continue;
        }
        return { res, finalUrl };
      }
      throw new Error('重定向次数过多');
    } catch (err) {
      lastError = err;
      if (err && err.name === 'AbortError') lastError = new Error('超时');
    } finally {
      clearTimeout(timer);
    }
  }
  throw lastError instanceof Error ? lastError : new Error('上游请求失败');
}

// ────────────────────────────── 环境配置解析 ──────────────────────────────

function parseEnvSources(env) {
  const raw = env.DEFAULT_SOURCES;
  if (!raw || !raw.trim()) return [];
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed
      .map((item, i) => {
        if (!item || typeof item !== 'object') return null;
        const name = typeof item.name === 'string' ? item.name.trim() : '';
        const url = typeof item.url === 'string' ? item.url.trim() : '';
        if (!name || !/^https?:\/\//.test(url)) return null;
        return {
          key: `env_${i}`,
          name,
          url: url.replace(/\/+$/, ''),
          detail: typeof item.detail === 'string' && item.detail.trim() ? item.detail.trim() : undefined,
          isAdult: item.isAdult === true,
        };
      })
      .filter(Boolean);
  } catch {
    return [];
  }
}

function parseEnvLiveSources(env) {
  const raw = env.DEFAULT_LIVE_SOURCES;
  if (!raw || !raw.trim()) return [];
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed
      .map((item, i) => {
        if (!item || typeof item !== 'object') return null;
        const name = typeof item.name === 'string' ? item.name.trim() : '';
        const url = typeof item.url === 'string' ? item.url.trim() : '';
        if (!name || !/^https?:\/\//.test(url)) return null;
        return {
          key: `envlive_${i}`,
          name,
          url: url.replace(/\/+$/, ''),
          epg: typeof item.epg === 'string' && item.epg.trim() ? item.epg.trim() : undefined,
        };
      })
      .filter(Boolean);
  } catch {
    return [];
  }
}

function parseEnvSubscriptions(env) {
  const raw = env.DEFAULT_SUBSCRIPTIONS;
  if (!raw || !raw.trim()) return [];
  try {
    const parsed = JSON.parse(raw);
    const list = Array.isArray(parsed) ? parsed : [];
    return list
      .map((item) => {
        if (typeof item === 'string') return { url: item.trim() };
        if (item && typeof item === 'object' && typeof item.url === 'string') {
          return { url: item.url.trim(), name: item.name, refreshDays: item.refreshDays };
        }
        return null;
      })
      .filter((x) => x && x.url);
  } catch {
    return [];
  }
}

// ────────────────────────────── CMS 解析 ──────────────────────────────

function parseSearchList(data, source) {
  if (!data || typeof data !== 'object') throw new Error('API返回的数据格式无效');
  const list = data.list;
  if (list !== null && list !== undefined && !Array.isArray(list)) throw new Error('API返回的数据格式无效');
  const s = (v) => (typeof v === 'string' && v.trim() ? v.trim() : undefined);
  return (Array.isArray(list) ? list : []).map((item) => {
    const vod = item || {};
    return {
      sourceKey: source.key,
      sourceName: source.name,
      vodId: String(vod.vod_id ?? ''),
      name: String(vod.vod_name ?? ''),
      pic: s(vod.vod_pic),
      typeName: s(vod.type_name),
      year: s(vod.vod_year),
      area: s(vod.vod_area),
      remarks: s(vod.vod_remarks),
      sourceUrl: source.url,
      isAdult: source.isAdult,
    };
  });
}

const M3U8_PATTERN = /\$https?:\/\/[^"'\s]+?\.m3u8/g;

function extractEpisodesFromPlayUrl(playUrl) {
  if (!playUrl) return [];
  const groups = playUrl
    .split('$$$')
    .map((group) =>
      group
        .split('#')
        .map((ep) => {
          const parts = ep.split('$');
          return parts.length > 1 ? parts[1] : '';
        })
        .filter((u) => u.startsWith('http://') || u.startsWith('https://')),
    )
    .filter((eps) => eps.length > 0);
  if (groups.length === 0) return [];
  return groups.find((eps) => eps.some((u) => u.includes('.m3u8'))) ?? groups[0];
}

function extractM3u8FromText(text) {
  if (!text) return [];
  return (text.match(M3U8_PATTERN) || []).map((l) => l.replace(/^\$/, ''));
}

function parseDetail(data, source) {
  const d = data || {};
  if (!Array.isArray(d.list) || d.list.length === 0) throw new Error('获取到的详情内容无效');
  const vod = d.list[0] || {};
  let episodes = extractEpisodesFromPlayUrl(String(vod.vod_play_url ?? ''));
  if (episodes.length === 0) episodes = extractM3u8FromText(String(vod.vod_content ?? ''));
  const s = (v) => (typeof v === 'string' && v.trim() ? v.trim() : undefined);
  return {
    episodes,
    videoInfo: {
      title: s(vod.vod_name),
      cover: s(vod.vod_pic),
      desc: s(vod.vod_content),
      typeName: s(vod.type_name),
      year: s(vod.vod_year),
      area: s(vod.vod_area),
      director: s(vod.vod_director),
      actor: s(vod.vod_actor),
      remarks: s(vod.vod_remarks),
      sourceKey: source.key,
      sourceName: source.name,
      sourceUrl: source.url,
    },
  };
}

function parseDetailPageHtml(html, source) {
  let matches = html.match(/\$(https?:\/\/[^"'\s]+?\.m3u8)/g) || [];
  if (matches.length === 0) {
    matches = html.match(/\$(https?:\/\/[^"'\s]+?\/\d{8}\/\d+_[a-f0-9]+\/index\.m3u8)/g) || [];
  }
  const episodes = [...new Set(matches.map((m) => m.replace(/^\$/, '')))];
  const titleMatch = html.match(/<h1[^>]*>([^<]+)<\/h1>/i);
  const coverMatch = html.match(/<meta[^>]+property="og:image"[^>]+content="([^"]+)"/i);
  const descMatch = html.match(/<meta[^>]+name="description"[^>]+content="([^"]*)"/i);
  return {
    episodes,
    videoInfo: {
      title: titleMatch ? titleMatch[1].trim() : source.name,
      cover: coverMatch ? coverMatch[1] : undefined,
      desc: descMatch ? descMatch[1].trim() : undefined,
      sourceKey: source.key,
      sourceName: source.name,
      sourceUrl: source.url,
    },
  };
}

const ADULT_KEYWORDS = [
  '伦理片', '福利', '倫理片', '福利片', '日本伦理', '日本福利', '日本福利片', '日本伦理片', '擦边短剧', '擦边',
  '韩国伦理', '里番动漫', '门事件', '萝莉少女', '制服诱惑', '国产传媒', 'cosplay', '黑丝诱惑', '无码',
  '日本无码', '有码', '日本有码', 'SWAG', '网红主播', '色情片', '同性片', '福利视频', '无码高清', '有码高清',
  '91视频', '自拍偷拍', 'mini传媒', '福利片',
];

function isAdultContent(typeName) {
  if (!typeName) return false;
  return ADULT_KEYWORDS.some((k) => typeName.includes(k));
}

function filterAdultResults(items, enabled) {
  if (!enabled) return items;
  return items.filter((it) => !isAdultContent(it.typeName));
}

function normalizeTitle(s) {
  return String(s || '').toLowerCase().replace(/[\s\p{P}\p{S}]+/gu, '');
}

/** 源站做 OR 模糊匹配时会返回一堆无关片，按关键词归一化后做包含匹配 */
function filterRelevantResults(items, wd) {
  const key = normalizeTitle(wd);
  if (!key) return items;
  return items.filter((it) => {
    const name = normalizeTitle(it.name || '');
    if (!name) return false;
    if (name.includes(key) || key.includes(name)) return true;
    // 季数别名：庆余年2 ↔ 庆余年 第二季
    const bare = /^(.*?)\s*([1-9]\d?)$/u.exec(wd.trim());
    if (bare) {
      const base = normalizeTitle(bare[1]);
      if (base && name.startsWith(base)) return true;
    }
    return false;
  });
}

// ────────────────────────────── M3U 解析 ──────────────────────────────

const ATTR_RE = /([a-zA-Z0-9_-]+)="([^"]*)"/g;
const ATTR_STRIP_RE = /[a-zA-Z0-9_-]+="[^"]*"/g;

function stableId(input) {
  let h = 5381;
  for (let i = 0; i < input.length; i++) h = ((h << 5) + h + input.charCodeAt(i)) >>> 0;
  return h.toString(36);
}

function normalizeStreamUrl(raw, baseUrl) {
  const t = String(raw || '').trim();
  if (!t) return undefined;
  try {
    // rtmp:// 是 Media3 原生支持的流协议（浙江广电等一批源在用），不能丢
    if (/^rtmps?:\/\//i.test(t)) return t;
    const resolved = new URL(t, baseUrl);
    if (resolved.protocol !== 'http:' && resolved.protocol !== 'https:') return undefined;
    return resolved.href;
  } catch {
    return undefined;
  }
}

function nameFromUrl(url) {
  try {
    const u = new URL(url);
    const last = u.pathname.split('/').filter(Boolean).pop();
    if (last) {
      const d = decodeURIComponent(last).replace(/\.(m3u8?|flv|ts|mp4)$/i, '');
      if (d) return d;
    }
    return u.hostname;
  } catch {
    return '未命名频道';
  }
}

/**
 * 从 #EXTINF 行取频道显示名。
 *
 * 不能用「去掉属性后取第一个逗号」：属性值内部可能含引号（实测有源把 tvg-logo 写成
 * 带 "Chrome/144.0.0.0 Safari/537.36" 的 URL），那样会把属性残片当成频道名。
 * 这里逐字符扫描，跳过引号内的内容，找第一个「引号外的逗号」——那才是属性与标题的分界。
 */
function extinfTitle(line) {
  let s = String(line).replace(/^#EXTINF\s*:\s*/i, '');
  s = s.replace(/^-?[\d.]+\s*,/, '');   // 去掉时长
  let inQuote = false;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === '"') { inQuote = !inQuote; continue; }
    if (ch === ',' && !inQuote) return s.slice(i + 1).trim().replace(/^"+|"+$/g, '');
  }
  return s.trim().replace(/^"+|"+$/g, '');
}

function parseM3u(content, baseUrl) {
  const channels = [];
  if (!content) return channels;
  const seen = new Set();
  let ctx = null;

  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;

    if (line.toUpperCase().startsWith('#EXTINF')) {
      const attrs = {};
      ATTR_RE.lastIndex = 0;
      let m;
      while ((m = ATTR_RE.exec(line))) attrs[m[1].toLowerCase()] = m[2].trim();
      const title = extinfTitle(line);
      ctx = { attrs, title, extGroup: '' };
      continue;
    }
    if (line.toUpperCase().startsWith('#EXTGRP:')) {
      const g = line.slice('#EXTGRP:'.length).trim();
      if (ctx && g && !ctx.attrs['group-title']) ctx.extGroup = g;
      continue;
    }
    if (line.startsWith('#')) continue;

    const url = normalizeStreamUrl(line, baseUrl);
    const cur = ctx;
    ctx = null;
    if (!url || seen.has(url)) continue;
    seen.add(url);

    const attrs = (cur && cur.attrs) || {};
    const tvgId = attrs['tvg-id'] || undefined;
    channels.push({
      id: tvgId || stableId(url),
      name: (cur && cur.title) || nameFromUrl(url),
      url,
      logo: attrs['tvg-logo'] ? normalizeStreamUrl(attrs['tvg-logo'], baseUrl) : undefined,
      group: attrs['group-title'] || (cur && cur.extGroup) || undefined,
      tvgId,
      rawName: attrs['tvg-name'] || undefined,
    });
  }
  return channels;
}

// ────────────────────────────── 订阅（source-list）解析 ──────────────────────────────

/** 兼容 LibreTV-SourceList JSON、TVBOX 配置、裸数组三种格式 */
function parseSourceListPayload(text) {
  let root = null;
  try {
    root = JSON.parse(text);
  } catch {
    return { sources: [], liveSources: [] };
  }
  const arr = Array.isArray(root) ? root : (root.sources || root.sites || []);
  const sources = [];
  for (const item of arr) {
    if (!item || typeof item !== 'object') continue;
    const url = (item.url || item.api || '').trim();
    if (!url || !/^https?:\/\//.test(url)) continue;
    if (item.api && item.type !== undefined && !['0', '1', ''].includes(String(item.type))) continue; // 跳过 Spider
    sources.push({
      name: String(item.name || item.key || url.replace(/^https?:\/\//, '').split('/')[0]),
      url: url.replace(/\/+$/, ''),
      detail: typeof item.detail === 'string' ? item.detail : undefined,
      isAdult: item.isAdult === true,
    });
  }

  let liveSources = [];
  const lives = Array.isArray(root) ? [] : (root.liveSources || root.lives || []);
  for (const item of lives) {
    if (!item) continue;
    const url = typeof item === 'string' ? item : (item.url || '');
    if (!url || !/^https?:\/\//.test(url)) continue;
    if (!/\.m3u8?(\?|$)/i.test(url)) continue;
    liveSources.push({
      name: typeof item === 'string' ? '' : String(item.name || ''),
      url,
      epg: typeof item === 'object' && item.epg ? String(item.epg) : undefined,
    });
  }
  return { sources, liveSources };
}

/**
 * 直播频道可用性基线（部署前做过一次分片级实测：取 manifest 末片 → 200 且有内容）。
 * 作用：首次请求就能给出真实可播的列表，不必等运行时探活轮转。
 */
const LIVE_SEED_URLS = new Set([
  "https://mediaserver.abnvideos.com/streams/abnchina.m3u8",
  "https://stream2.jlntv.cn/baicheng1/sd/live.m3u8",
  "http://113.64.146.48:1688/hls/4/index.m3u8",
  "http://hwapi.yntv.net/ew265l/848y54.m3u8",
  "https://h5cul1yar48um3t.wcetv.com/hls/gdsatellite.m3u8",
  "http://111.59.24.227:8181/tsfile/live/1001_1.m3u8?key=txiptv&playlive=1&authid=0",
  "https://stream.jmtv.com.cn/xwzh/sd/live.m3u8?_upt=341f4b8e1791883036",
  "http://110.185.237.164:8888/hls/30/index.m3u8",
  "https://liveplus.lzr.com.cn/xwzh/HD/live.m3u8",
  "https://liveplus.lzr.com.cn/wlpd/HD/live.m3u8",
  "http://video10.qtv.com.cn/drm/qtv1at/manifest.m3u8",
  "http://video10.qtv.com.cn/drm/qtv2at/manifest.m3u8",
  "http://video10.qtv.com.cn/drm/qtv3at/manifest.m3u8",
  "http://video10.qtv.com.cn/drm/qtv4at/manifest.m3u8",
  "http://video10.qtv.com.cn/drm/qtv5at/manifest.m3u8",
  "http://video10.qtv.com.cn/drm/qtv6at/manifest.m3u8",
  "http://stream2.jlntv.cn/sptv/sd/live.m3u8?_upt=f27750421743154598",
  "http://120.70.60.179:9901/tsfile/live/1002_1.m3u8?key=txiptv&playlive=1&authid=0",
  "http://120.70.60.179:9901/tsfile/live/1002_1.m3u8?authid=0&key=txiptv&playlive=1",
]);

/** 频道可用性探活缓存：url -> { ok, ts }。TTL 6 小时（源会随时间失效，缓存不宜过长）。 */
const LIVE_PROBE_TTL = 6 * 60 * 60 * 1000;
const liveProbeCache = new Map();
/** 轮转游标：保证每次请求只探一批，避免超出 Workers 单请求 50 子请求的上限。 */
let liveProbeCursor = 0;

// ────────────────────────────── 内存缓存（单 isolate 内有效） ──────────────────────────────

const cache = new Map();
function cacheGet(key) {
  const hit = cache.get(key);
  if (!hit) return undefined;
  if (Date.now() > hit.expiresAt) {
    cache.delete(key);
    return undefined;
  }
  return hit.value;
}
function cacheSet(key, value, ttlMs) {
  if (cache.size > 400) cache.clear();
  cache.set(key, { value, expiresAt: Date.now() + ttlMs });
}

// ────────────────────────────── 各接口实现 ──────────────────────────────

async function handleStatus(env, request) {
  const passwordRequired = getPassword(env).length > 0;
  const verified = passwordRequired && (await isVerified(env, request));
  return json({
    passwordRequired,
    verified,
    version: env.APP_VERSION || '2.21.1-pages',
    defaultSources: parseEnvSources(env),
    defaultLiveSources: parseEnvLiveSources(env),
    defaultSubscriptions: parseEnvSubscriptions(env),
    defaultRecommendSource: env.DEFAULT_RECOMMEND_SOURCE || 'douban',
    defaultImageMode: env.DEFAULT_IMAGE_MODE || null,
  });
}

async function handleAuth(env, request) {
  if (!getPassword(env)) return jsonError('服务器未设置 PASSWORD 环境变量', 503);
  let body = {};
  try {
    body = await request.json();
  } catch {
    return jsonError('请求格式错误', 400);
  }
  if (!(await checkPassword(env, body.password))) return jsonError('密码错误', 401);
  const { token, expiresAt } = await signSession(env);
  const secure = new URL(request.url).protocol === 'https:' ? '; Secure' : '';
  return json(
    { success: true },
    200,
    {
      'Set-Cookie': `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${Math.floor(
        (expiresAt - Date.now()) / 1000,
      )}${secure}`,
    },
  );
}

/** 单源搜索：只抓第 1 页（Workers 免费版单请求最多 50 个子请求） */
async function searchOneSource(source, wd) {
  const started = Date.now();
  const base = String(source.url || '').replace(/\/+$/, '');
  if (!/^https?:\/\//.test(base)) {
    return { sourceKey: source.key, ok: false, list: [], error: '无效的源地址' };
  }
  if (!isAllowedUrl(base)) {
    return { sourceKey: source.key, ok: false, list: [], error: '目标地址不在允许范围内（仅支持公网 http/https）' };
  }
  try {
    const api = `${base}?ac=videolist&wd=${encodeURIComponent(wd)}&pg=1`;
    const { res } = await fetchUpstream(api, { timeoutMs: 10000, headers: CMS_HEADERS });
    if (!res.ok) return { sourceKey: source.key, ok: false, list: [], error: `HTTP ${res.status}` };
    const data = await res.json();
    const list = parseSearchList(data, source);
    return { sourceKey: source.key, ok: true, list, ms: Date.now() - started };
  } catch (err) {
    const msg = err instanceof Error ? err.message : '请求失败';
    return {
      sourceKey: source.key,
      ok: false,
      list: [],
      error: msg,
      timedOut: /超时|timeout/i.test(msg),
      ms: Date.now() - started,
    };
  }
}

async function handleSearch(env, request) {
  const guarded = await guard(env, request);
  if (guarded) return guarded;

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonError('请求格式错误', 400);
  }
  const wd = String(body.wd || '').trim();
  if (!wd || wd.length > 100) return jsonError('搜索关键词无效', 400);

  const sources = Array.isArray(body.sources) ? body.sources.slice(0, 40) : [];
  if (sources.length === 0) return jsonError('未指定搜索源', 400);

  const filterAdult = body.filterAdult !== false;
  const outcomes = await Promise.all(sources.map((s) => searchOneSource(s, wd)));

  const seen = new Set();
  let list = outcomes.flatMap((o) => o.list).filter((item) => {
    const key = `${item.sourceKey}_${item.vodId}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  list = filterAdultResults(list, filterAdult);
  list = filterRelevantResults(list, wd);

  const exact = normalizeTitle(wd);
  list.sort((a, b) => {
    const aExact = normalizeTitle(a.name || '') === exact ? 0 : 1;
    const bExact = normalizeTitle(b.name || '') === exact ? 0 : 1;
    if (aExact !== bExact) return aExact - bExact;
    const c = (a.name || '').localeCompare(b.name || '', 'zh-Hans-CN');
    if (c !== 0) return c;
    return (a.sourceName || '').localeCompare(b.sourceName || '', 'zh-Hans-CN');
  });

  const failures = outcomes
    .filter((o) => !o.ok)
    .map((o) => ({ sourceKey: o.sourceKey, error: o.error || '请求失败', timedOut: o.timedOut }));

  return json({ list, failures });
}

async function handleDetail(env, request) {
  const guarded = await guard(env, request);
  if (guarded) return guarded;

  const sp = new URL(request.url).searchParams;
  const id = (sp.get('id') || '').trim();
  const baseUrl = (sp.get('baseUrl') || '').trim();

  let source = null;
  try {
    const obj = JSON.parse(sp.get('source') || '');
    if (obj && /^https?:\/\//.test(obj.url || '')) source = obj;
  } catch {
    source = null;
  }
  if (!id || !/^[\w-]+$/.test(id)) return jsonError('无效的视频ID', 400);
  if (!source) return jsonError('无效的点播源配置', 400);

  try {
    const detailRoot = (source.detail || baseUrl || new URL(source.url).origin).replace(/\/+$/, '');
    const cacheKey = `detail:${source.url}|${detailRoot}|${id}`;
    const cached = cacheGet(cacheKey);
    if (cached) return json(cached);

    if (!isAllowedUrl(source.url)) return jsonError('目标地址不在允许范围内（仅支持公网 http/https）', 400);

    let resolved = null;

    // 1) 标准列表接口
    try {
      const api = `${source.url.replace(/\/+$/, '')}?ac=videolist&ids=${encodeURIComponent(id)}`;
      const { res } = await fetchUpstream(api, { timeoutMs: 12000, headers: CMS_HEADERS });
      if (res.ok) {
        const data = await res.json();
        try {
          const detail = parseDetail(data, source);
          if (detail.episodes.length > 0) resolved = detail;
        } catch {
          /* 列表接口无内容 → 降级详情页 */
        }
      }
    } catch {
      /* 忽略，继续详情页 */
    }

    // 2) 详情页 HTML 提取
    if (!resolved && /^https?:\/\//.test(detailRoot) && isAllowedUrl(detailRoot)) {
      try {
        const detailUrl = `${detailRoot}/index.php/vod/detail/id/${id}.html`;
        const { res } = await fetchUpstream(detailUrl, { timeoutMs: 12000, headers: { 'User-Agent': UA } });
        if (res.ok) {
          const html = await res.text();
          resolved = parseDetailPageHtml(html, source);
        }
      } catch {
        /* 忽略 */
      }
    }

    if (!resolved || resolved.episodes.length === 0) return jsonError('未找到播放资源', 404);
    cacheSet(cacheKey, resolved, 60 * 1000);
    return json(resolved);
  } catch (err) {
    return jsonError(err instanceof Error ? err.message : '获取详情失败', 502);
  }
}

async function handleDouban(env, request) {
  const guarded = await guard(env, request);
  if (guarded) return guarded;

  const sp = new URL(request.url).searchParams;
  const type = sp.get('type') === 'tv' ? 'tv' : 'movie';
  const tag = (sp.get('tag') || '热门').slice(0, 20);
  const pageStart = Math.max(0, parseInt(sp.get('pageStart') || '0', 10) || 0);
  const pageSize = Math.min(50, Math.max(1, parseInt(sp.get('pageSize') || '25', 10) || 25));

  const cacheKey = `douban:${type}:${tag}:${pageStart}:${pageSize}`;
  const cached = cacheGet(cacheKey);
  if (cached) return json({ items: cached });

  const target = `https://movie.douban.com/j/search_subjects?type=${type}&tag=${encodeURIComponent(
    tag,
  )}&sort=recommend&page_limit=${pageSize}&page_start=${pageStart}`;

  let raw = null;
  try {
    const { res } = await fetchUpstream(target, {
      timeoutMs: 10000,
      headers: { 'User-Agent': UA, Referer: 'https://movie.douban.com/', Accept: 'application/json' },
    });
    if (res.ok) {
      const data = await res.json();
      raw = data.subjects;
    }
  } catch {
    /* 继续降级 */
  }

  // 降级：60s 公共实例
  if (!raw && env['60S_API_BASE']) {
    try {
      const base = String(env['60S_API_BASE']).replace(/\/+$/, '');
      const { res } = await fetchUpstream(`${base}/api/v1/douban/movie?tag=${encodeURIComponent(tag)}`, {
        timeoutMs: 10000,
        headers: { Accept: 'application/json' },
      });
      if (res.ok) {
        const data = await res.json();
        raw = Array.isArray(data.data) ? data.data : null;
      }
    } catch {
      /* 忽略 */
    }
  }

  if (!raw) return jsonError('豆瓣推荐获取失败', 502);

  const items = raw.map((s) => ({
    id: String(s.id ?? ''),
    title: String(s.title ?? ''),
    cover: String(s.cover ?? s.pic ?? ''),
    rating: s.rate && s.rate !== '0' ? String(s.rate) : undefined,
    isTv: type === 'tv',
  }));
  cacheSet(cacheKey, items, 10 * 60 * 1000);
  return json({ items });
}


/**
 * 单频道分片级探活。
 *
 * 为什么必须探到分片：很多海外中转 IPTV 源的 HLS 滚动窗口极小
 * （CCTV-2 那个源 TARGETDURATION=10，manifest 里只有 3 个分片，8 秒就滚掉一个），
 * manifest 拿得到（HTTP 200）但分片已被回收（404）→ 播放器起播成功后约 30 秒必然报
 * ERROR_CODE_IO_UNSPECIFIED。只看 manifest 会把这类坏源放给客户端。
 *
 * 手法与上游 /api/live/probe 一致：
 * - 取 manifest → 解析出分片 URL（相对路径按 manifest 的 URL 解析）
 * - 取**最后一个**分片（最新的，最不容易已过期）
 * - 用 Range: bytes=0-1 轻量请求，拿到响应头即断开
 * - 校验 #EXTM3U 前缀与 content-type，避免把 HTML/JSON 错误页当成可用
 */
async function probeLiveChannel(channelUrl) {
  const cached = liveProbeCache.get(channelUrl);
  if (cached && Date.now() - cached.ts < LIVE_PROBE_TTL) return cached.ok;

  let ok = false;
  try {
    const base = channelUrl;
    const { res } = await fetchUpstream(base, {
      timeoutMs: 8000,
      headers: { 'User-Agent': UA, Accept: '*/*' },
    });
    if (res.ok) {
      const text = (await res.text()).slice(0, 200000);
      if (text.trim().startsWith('#EXTM3U')) {
        const segs = text.split(/\r?\n/).map((l) => l.trim())
          .filter((l) => l && !l.startsWith('#'));
        // Media3 的 HlsPlaylistTracker 在媒体 playlist 分片数 <= MIN_PLAYLIST_SEGMENT_COUNT(=3) 时
        // 会抛 PlaylistStuckException（表现为 ERROR_CODE_IO_UNSPECIFIED）。
        // 滚动窗口只有 3 个分片的源必然在起播约 30 秒后被判「卡住」而中断 —— 与其等播放器报错，
        // 不如在服务端就只放行分片数充足的源。
        if (segs.length >= MIN_PLAYLIST_SEGMENTS) {
          const last = new URL(segs[segs.length - 1], base).href;
          // 轻量取分片头部
          const sres = await fetch(last, {
            headers: { 'User-Agent': UA, Range: 'bytes=0-1' },
            redirect: 'follow',
          });
          const buf = new Uint8Array(await sres.arrayBuffer());
          ok = sres.ok && buf.length > 0;
          // 分片请求失败后不再重试，直接记为不可用
          try { sres.body && sres.body.cancel(); } catch { /* ignore */ }
        }
      }
    }
  } catch {
    ok = false;
  }
  liveProbeCache.set(channelUrl, { ok, ts: Date.now() });
  return ok;
}

/**
 * 对一批频道做分片级探活。受 Workers 单请求 50 子请求限制，每批最多 16 个频道
 * （每频道 2 个子请求：manifest + 分片）。
 */
async function probeLiveBatch(channels) {
  const BATCH = 16;
  const out = new Map();
  let i = liveProbeCursor;
  for (let n = 0; n < Math.min(BATCH, channels.length); n++) {
    const ch = channels[i % channels.length];
    i++;
    if (!ch) break;
    if (!liveProbeCache.has(ch.url)) {
      const ok = await probeLiveChannel(ch.url);
      out.set(ch.url, ok);
    }
  }
  liveProbeCursor = channels.length ? i % channels.length : 0;
  return out;
}


/**
 * 直播源探活（独立端点，不影响 /api/live/playlist 的列表内容）。
 * GET /api/live/probe?url=<m3u>&limit=50
 *   - 逐频道取 manifest → 记录分片数 / 是否 DRM / 末片是否可取 / playlist 序号是否推进
 *   - limit 限制本轮探活数量（受 Workers 单请求 50 子请求约束，每频道约 2 个子请求）
 * 返回 { total, probed, alive, dead, results: [...] }
 */
async function handleLiveProbe(env, request) {
  const guarded = await guard(env, request);
  if (guarded) return guarded;

  const sp = new URL(request.url).searchParams;
  const url = (sp.get('url') || '').trim();
  if (!url) return jsonError('缺少 url 参数', 400);
  if (!isAllowedUrl(url)) return jsonError('目标地址不在允许范围内（仅支持公网 http/https）', 403);
  const limit = Math.min(50, Math.max(1, parseInt(sp.get('limit') || '20', 10) || 20));

  let text;
  try {
    const { res } = await fetchUpstream(url, { timeoutMs: 20000, headers: { 'User-Agent': UA } });
    if (!res.ok) return jsonError(`订阅地址请求失败: ${res.status}`, 502);
    text = await res.text();
  } catch (err) {
    return jsonError(`订阅地址请求失败: ${err instanceof Error ? err.message : '未知错误'}`, 502);
  }

  const all = parseM3u(text, url);
  const results = [];
  const batch = all.slice(0, limit);
  for (const ch of batch) {
    const r = await probeLiveChannel(ch.url);
    results.push({ name: ch.name, url: ch.url, ok: r });
  }
  const alive = results.filter((r) => r.ok).length;
  return json({ total: all.length, probed: results.length, alive, dead: results.length - alive, results });
}

async function handleLivePlaylist(env, request) {
  const guarded = await guard(env, request);
  if (guarded) return guarded;

  const sp = new URL(request.url).searchParams;
  const url = (sp.get('url') || '').trim();
  if (!url) return jsonError('缺少 url 参数', 400);
  if (!isAllowedUrl(url)) return jsonError('目标地址不在允许范围内（仅支持公网 http/https）', 403);

  const cacheKey = `live:playlist:${url}`;
  const cached = cacheGet(cacheKey);
  if (cached) return json(cached, 200, { 'Cache-Control': 'no-store' });

  let text;
  try {
    const { res } = await fetchUpstream(url, { timeoutMs: 20000, headers: { 'User-Agent': UA }, retries: 1 });
    if (!res.ok) return jsonError(`订阅地址请求失败: ${res.status}`, 502);
    text = await res.text();
  } catch (err) {
    return jsonError(`订阅地址请求失败: ${err instanceof Error ? err.message : '未知错误'}`, 502);
  }

  const all = parseM3u(text, url);

  // 只保留实测能播的频道：滚动窗口极小的源会在起播约 30 秒后因分片 404 而中断。
  // 未探活过的频道先用部署期实测基线兜底（LIVE_SEED_URLS），其余等轮转探活后再收录。
  // ⚠️ 列表返回全量，不做过滤。
  // 曾经按「分片数 / 末片可达」筛掉过一批源，但那些判据与 Media3 实际报错的对应关系没有完全验证，
  // 过滤反而把可用的源也藏起来了。探活能力保留在 /api/live/probe 端点，按需调用。
  const channels = all;

  const groups = [...new Set(channels.map((c) => c.group).filter(Boolean))].sort((a, b) => a.localeCompare(b, 'zh'));
  const playlist = { channels, groups };
  cacheSet(cacheKey, playlist, 10 * 60 * 1000);
  return json(playlist, 200, { 'Cache-Control': 'no-store' });
}

async function handleSourceList(env, request) {
  const guarded = await guard(env, request);
  if (guarded) return guarded;

  const url = (new URL(request.url).searchParams.get('url') || '').trim();
  if (!url) return jsonError('缺少 url 参数', 400);
  if (!isAllowedUrl(url)) return jsonError('目标地址不在允许范围内（仅支持公网 http/https）', 403);

  let text;
  try {
    const { res } = await fetchUpstream(url, { timeoutMs: 15000, headers: { 'User-Agent': UA, Accept: 'application/json' } });
    if (!res.ok) return jsonError(`订阅地址请求失败: ${res.status}`, 502);
    text = await res.text();
  } catch (err) {
    return jsonError(`订阅地址请求失败: ${err instanceof Error ? err.message : '未知错误'}`, 502);
  }

  const parsed = parseSourceListPayload(text);
  return json({ sources: parsed.sources, liveSources: parsed.liveSources });
}

async function handleSourceTest(env, request) {
  const guarded = await guard(env, request);
  if (guarded) return guarded;

  let url = '';
  try {
    const body = await request.json();
    url = (body.url || '').trim().replace(/\/+$/, '');
  } catch {
    return jsonError('请求格式错误', 400);
  }
  if (!/^https?:\/\//.test(url)) return jsonError('无效的源地址', 400);
  if (!isAllowedUrl(url)) return json({ ok: false, ms: 0, error: '目标地址不在允许范围内（仅支持公网 http/https）' });

  const started = Date.now();
  try {
    const { res } = await fetchUpstream(`${url}?ac=videolist&wd=test`, {
      timeoutMs: 6000,
      headers: CMS_HEADERS,
    });
    const ms = Date.now() - started;
    if (!res.ok) return json({ ok: false, ms, error: `HTTP ${res.status}` });
    const data = await res.json();
    const list = parseSearchList(data, { key: 'test', name: 'test', url });
    return json({ ok: true, ms, count: list.length });
  } catch (err) {
    const msg = err instanceof Error ? err.message : '请求失败';
    return json({ ok: false, ms: Date.now() - started, error: /超时|timeout/i.test(msg) ? '超时' : msg });
  }
}

// ────────────────────────────── 路由 ──────────────────────────────

const ROUTES = {
  status: { methods: ['GET'], handler: handleStatus },
  auth: { methods: ['POST'], handler: handleAuth },
  search: { methods: ['POST'], handler: handleSearch },
  detail: { methods: ['GET'], handler: handleDetail },
  douban: { methods: ['GET'], handler: handleDouban },
  'live/playlist': { methods: ['GET'], handler: handleLivePlaylist },
  'live/probe': { methods: ['GET'], handler: handleLiveProbe },
  'source-list': { methods: ['GET'], handler: handleSourceList },
  'source/test': { methods: ['POST'], handler: handleSourceTest },
};

export async function onRequest(context) {
  const { request, env, params } = context;
  const url = new URL(request.url);
  const key = (params.path || []).join('/');

  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': '*',
      },
    });
  }

  const route = ROUTES[key];
  if (!route) return jsonError(`未知的接口: /api/${key}`, 404);
  if (!route.methods.includes(request.method)) {
    return jsonError(`${request.method} 不支持该接口`, 405);
  }

  try {
    return await route.handler(env, request);
  } catch (err) {
    return jsonError(err instanceof Error ? err.message : '服务器内部错误', 500);
  }
}
