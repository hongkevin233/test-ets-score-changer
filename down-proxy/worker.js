// down.dianetwork.top -> release.dianetwork.top (R2) 反向代理
// - GET/HEAD 透传, 完整 200 响应写入边缘缓存 (86400s), 重复下载直接命中边缘
// - Range 断点续传请求直接回源, 不缓存

const ORIGIN = "https://release.dianetwork.top";
const CACHE_TTL = 86400;

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const originUrl = ORIGIN + url.pathname + url.search;

    if (request.method !== "GET" || request.headers.get("range")) {
      return fetch(originUrl, request);
    }

    const cache = caches.default;
    const cached = await cache.match(request);
    if (cached) {
      return cached;
    }

    const res = await fetch(originUrl, request);
    if (res.status === 200) {
      await cache.put(request, res.clone());
      const out = new Response(res.body, res);
      out.headers.set("Cache-Control", `public, max-age=${CACHE_TTL}`);
      return out;
    }
    return res;
  },
};
