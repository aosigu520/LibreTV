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
 *     GET  /api/douban?type&tag&...       -> {items:[{id,title,cover,rating}]}，cover 保持原始 URL
 *     GET  /api/proxy?url=<资源地址>      -> 图片字节 / HLS manifest（分片 URI 已改写为本站代理）/ ts 等二进制
 *                                            DpadTV 1.3.0 把封面、直播 manifest、分片全走这里；
 *                                            不实现则首页海报全空 + 直播全部 502 无法起播
 *     GET  /api/image?url=<资源地址>      -> 同上，兼容别名
 *     GET  /api/live/playlist?url=        -> {channels:[{id,name,url,logo,group,tvgId}], groups:[...]}
 *                                            channels 已置顶：央视 → 湖南台 → 中国台湾地区 → 其余原序
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

// ────────────────────────────── 直播频道置顶排序 ──────────────────────────────
/**
 * /api/live/playlist 返回的 channels 顺序，就是电视端直播列表的显示顺序。
 * iptv-org 的 M3U 按频道英文字母排序，CCTV 被 "A/B" 开头的频道挤到中间，
 * 湖南台、中国台湾地区频道更靠后，用遥控器翻很久才能看到。
 *
 * 这里按收视习惯把三类频道提到最前，其余频道保持订阅源原顺序（稳定排序）：
 *   tier 0  中央电视台（CCTV / CGTN / 央视），内部按主频道号 1..17 升序
 *   tier 1  湖南广播电视台旗下（Hunan TV / 湖南卫视 / 芒果），卫视优先
 *   tier 2  中国台湾地区频道（iptv-org 的 tvg-id 以 .tw@ 结尾，或名称含台湾台名）
 *   tier 3  其它频道，顺序完全不变
 *
 * ⚠️ 只调整数组顺序：不增删频道、不改写 name / url / group / logo 等任何字段，
 *   也不影响 /api/live/probe 的探活结果。
 */
const PIN_TIER_CCTV = 0;
const PIN_TIER_HUNAN = 1;
const PIN_TIER_TAIWAN = 2;
const PIN_TIER_OTHER = 3;

function isCctvChannel(c) {
  return /^(CCTV|CGTN|CNTV)/i.test(c.name || '')
    || /^(CCTV|CGTN|CNTV)/i.test(c.tvgId || '')
    || /央视|中央电视|中央广播电视总台/.test(c.name || '');
}

function isHunanChannel(c) {
  return /hunan|湖南|芒果|mango|金鹰/i.test(
    `${c.name || ''} ${c.tvgId || ''} ${c.rawName || ''}`,
  );
}

function isTaiwanRegionChannel(c) {
  // iptv-org 里中国台湾地区频道的 tvg-id 统一形如 FTV.tw@SD / TVBSNews.tw@SD，最可靠
  const id = c.tvgId || '';
  if (/\.tw@/i.test(id) || /\.tw$/i.test(id)) return true;
  return /taiwan|台湾|台视|中视|华视|民视|三立|东森|中天|TVBS|八大电视|年代电视|非凡电视|公视|客家电视|原住民族/i
    .test(c.name || '');
}

/** 央视内部排序：CCTV-1..17 → CCTV+ 外宣 → 其它专业频道（台球/高尔夫/风云剧场等） */
function cctvSubRank(name) {
  const main = String(name).match(/^CCTV-(\d+)/i);
  if (main) return Number(main[1]);
  const plus = String(name).match(/^CCTV\+\s*(\d+)/i);
  if (plus) return 100 + Number(plus[1]);
  return 200;
}

function pinLiveChannels(channels) {
  return channels
    .map((c, i) => {
      let tier = PIN_TIER_OTHER;
      let sub = 0;
      if (isCctvChannel(c)) {
        tier = PIN_TIER_CCTV;
        sub = cctvSubRank(c.name);
      } else if (isHunanChannel(c)) {
        tier = PIN_TIER_HUNAN;
        sub = /^Hunan TV\b|湖南卫视/i.test(c.name || '') ? 0 : 1;
      } else if (isTaiwanRegionChannel(c)) {
        tier = PIN_TIER_TAIWAN;
      }
      return { c, i, tier, sub };
    })
    .sort((a, b) => a.tier - b.tier || a.sub - b.sub || a.i - b.i)
    .map((x) => x.c);
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

// ────────────────────── 通用资源代理（图片 + HLS 直播流） ──────────────────────
/**
 * 反编译 DpadTV 1.3.0 的 classes3.dex 确认：客户端把「所有」外链资源统一包成
 *   GET /api/proxy?url=<encoded>
 * 既包括豆瓣封面（Api.imageBytes），也包括直播/点播的 m3u8 manifest 与 HLS 分片。
 *
 * 历史教训（2026-11-15）：
 *  第一版 /api/proxy 只放行 image/*。结果 1.3.0 的直播流全部拿到 502，
 *  logcat 里连续 100 次 ERROR_CODE_IO_BAD_HTTP_STATUS / mediaPos=0.00，
 *  连起播都做不到，更谈不上验证历史遗留的「播 30 秒断流」。
 *
 * 现在按资源类型分三路：
 *   - image/*         -> 返回字节；豆瓣域带 Referer（否则 418 空图）
 *   - HLS playlist    -> 读文本，把每行分片 URI 与 EXT-X-KEY/MAP 的 URI
 *                        改写成「本站 /api/proxy?url=绝对源地址」。
 *                        不改写的话播放器会拿 /api/xxx.ts 请求本站 → 404
 *   - 其它二进制       -> 原样/流式转发，透传 Range 与 Content-Range
 *  每一层目标都过 isAllowedUrl（SSRF），并禁止嵌套代理自身。
 *  免登录：客户端的图片/分片请求不一定带会话 Cookie。
 *
 *  ⚠️ 但完整代理只对图片默认启用。媒体资源默认 302 交还电视直连（理由见
 *  handleProxy 内的实测数据），上面的 HLS 改写分支只在环境变量
 *  LIVE_PROXY_MODE=full 时才会走到，保留它便于日后排查/换部署方案。
 */
const DOUBAN_IMAGE_SUFFIXES = ['.doubanio.com', '.douban.com'];

function isDoubanImageHost(hostname) {
  const h = String(hostname || '').toLowerCase();
  return DOUBAN_IMAGE_SUFFIXES.some((s) => h === s.slice(1) || h.endsWith(s));
}

/** 客户端可能对 url 参数做了二次编码，最多解 3 层直到出现 :// */
function decodeUrlParam(raw) {
  let v = String(raw || '');
  for (let i = 0; i < 3; i++) {
    if (!/%3a%2f%2f/i.test(v)) break;
    try {
      v = decodeURIComponent(v);
    } catch {
      break;
    }
  }
  return v;
}

function isHlsPlaylistUrl(target) {
  return /\.m3u8?$/i.test(target.pathname);
}

/** 把 m3u8 内所有 URI 改成走本站 /api/proxy 的绝对地址 */
function rewriteHlsPlaylist(text, baseUrl, origin) {
  const wrap = (abs) => `${origin}/api/proxy?url=${encodeURIComponent(abs)}`;
  return text
    .split(/\r?\n/)
    .map((line) => {
      const trimmed = line.trim();
      if (!trimmed) return line;
      if (trimmed.startsWith('#')) {
        if (!/URI\s*=/i.test(trimmed)) return line;
        return line.replace(/URI\s*=\s*"([^"]+)"/gi, (match, uri) => {
          try {
            const abs = new URL(uri, baseUrl).href;
            if (!/^https?:$/.test(new URL(abs).protocol) || !isAllowedUrl(abs)) return match;
            return `URI="${wrap(abs)}"`;
          } catch {
            return match;
          }
        });
      }
      try {
        const abs = new URL(trimmed, baseUrl).href;
        if (!/^https?:$/.test(new URL(abs).protocol) || !isAllowedUrl(abs)) return line;
        return wrap(abs);
      } catch {
        return line;
      }
    })
    .join('\n');
}

/** GET /api/proxy?url=<资源地址> —— 免登录，图片 / HLS 通用 */
async function handleProxy(env, request) {
  const reqUrl = new URL(request.url);
  const raw = decodeUrlParam(reqUrl.searchParams.get('url'));
  if (!raw || raw.length > 2048) return new Response('缺少资源地址', { status: 400 });
  let target;
  try {
    target = new URL(raw);
  } catch {
    return new Response('资源地址非法', { status: 400 });
  }
  // 防止 /api/proxy?url=.../api/proxy?... 造成无限递归
  if (/\/api\/proxy\/?$/i.test(target.pathname)) {
    return new Response('不允许嵌套代理', { status: 403 });
  }
  if (!isAllowedUrl(target.href)) {
    return new Response('资源地址不在允许范围内', { status: 403 });
  }

  const douban = isDoubanImageHost(target.hostname);

  // 2026-11-15 实测结论（不是推测）：
  //  Cloudflare 回源国内 IPTV 的 ts 分片要 3.9–7.4s / 约 600KB，
  //  而分片本身时长只有 4–6s，另有约 1/3 请求直接超时；
  //  走代理必然把播放缓冲耗光 → 反复重连、起播失败。
  //  Mac 直连同一分片只需 0.42s。
  // 因此媒体资源默认 302 交还电视直连源站（恢复 1.2.0 的行为），
  // 只有豆瓣图片必须留在服务端代理（要带 Referer，否则 418 空图）。
  // 已知限制：Media3 默认不允许 https→http 跨协议重定向，http 源可能失败；
  // 需要强制完整代理排查时，设环境变量 LIVE_PROXY_MODE=full。
  const looksLikeImage = /\.(?:jpe?g|png|webp|gif|avif|bmp|ico)(?:\?|$)/i.test(target.href);
  if (!douban && !looksLikeImage && env.LIVE_PROXY_MODE !== 'full') {
    return new Response(null, {
      status: 302,
      headers: {
        Location: target.href,
        'Access-Control-Allow-Origin': '*',
        'Cache-Control': 'no-store',
      },
    });
  }

  const isManifest = isHlsPlaylistUrl(target);
  const headers = { 'User-Agent': UA };
  if (douban) {
    headers.Referer = 'https://movie.douban.com/';
    headers.Accept = 'image/avif,image/webp,image/apng,image/*,*/*;q=0.8';
  } else if (isManifest) {
    headers.Accept = 'application/vnd.apple.mpegurl,application/x-mpegURL,*/*';
  } else {
    headers.Accept = '*/*';
  }
  const range = request.headers.get('Range');
  if (range && range.length <= 128) headers.Range = range;

  let res;
  let finalUrl;
  try {
    const r = await fetchUpstream(target.href, {
      timeoutMs: isManifest ? 12000 : 20000,
      headers,
      retries: isManifest ? 1 : 0,
    });
    res = r.res;
    finalUrl = r.finalUrl;
  } catch {
    return new Response('上游资源获取失败', { status: 502 });
  }
  if (!res.ok) {
    return new Response(`上游返回 ${res.status}`, { status: res.status === 404 ? 404 : 502 });
  }

  const type = (res.headers.get('content-type') || '').split(';')[0].trim();
  const common = {
    'Access-Control-Allow-Origin': '*',
    'X-Content-Type-Options': 'nosniff',
  };
  const contentRange = res.headers.get('Content-Range');
  const passthrough = () => ({
    ...common,
    'Content-Type': type || 'application/octet-stream',
    'Cache-Control': 'public, max-age=2',
    ...(contentRange ? { 'Content-Range': contentRange } : {}),
  });

  // 1) 图片
  if (/^image\//i.test(type)) {
    try {
      const buf = await res.arrayBuffer();
      // 挡掉 418 防盗链空响应（14 字节）和异常大文件
      if (buf.byteLength < 100 || buf.byteLength > 8 * 1024 * 1024) {
        return new Response('图片内容异常', { status: 502 });
      }
      return new Response(buf, {
        status: 200,
        headers: {
          ...common,
          'Content-Type': type,
          'Cache-Control': 'public, max-age=86400, s-maxage=604800',
        },
      });
    } catch {
      return new Response('图片读取失败', { status: 502 });
    }
  }

  // 2) 小响应：探测是不是 HLS playlist。
  //    很多 IPTV 源不带 .m3u8 扩展名、content-type 也乱填，只看 URL 会漏。
  const declaredLen = Number(res.headers.get('content-length') || 0);
  if (isManifest || declaredLen === 0 || declaredLen <= 512 * 1024) {
    let buf;
    try {
      buf = await res.arrayBuffer();
    } catch {
      return new Response('资源读取失败', { status: 502 });
    }
    const head = dec.decode(new Uint8Array(buf, 0, Math.min(buf.byteLength, 32)));
    if (head.includes('#EXTM3U')) {
      const rewritten = rewriteHlsPlaylist(dec.decode(buf), finalUrl, reqUrl.origin);
      return new Response(rewritten, {
        status: 200,
        headers: {
          ...common,
          'Content-Type': 'application/vnd.apple.mpegurl; charset=utf-8',
          // 直播 manifest 是滚动窗口，绝不能缓存
          'Cache-Control': 'no-store, no-cache, must-revalidate',
        },
      });
    }
    return new Response(buf, { status: res.status, headers: passthrough() });
  }

  // 3) 大分片：流式转发，避免整段读进内存
  return new Response(res.body, { status: res.status, headers: passthrough() });
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

  // ⚠️ 列表返回全量，不做过滤。
  // 曾经按「分片数 / 末片可达」筛掉过一批源，但那些判据与 Media3 实际报错的对应关系没有完全验证，
  // 过滤反而把可用的源也藏起来了。探活能力保留在 /api/live/probe 端点，按需调用。
  // 唯一会动的是顺序：央视 → 湖南台 → 中国台湾地区频道置顶，其余保持订阅源原顺序。
  const channels = pinLiveChannels(all);

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
  proxy: { methods: ['GET'], handler: handleProxy },
  image: { methods: ['GET'], handler: handleProxy },
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
