// down.dianetwork.top -> release.dianetwork.top (R2) 反向代理
// - GET/HEAD 透传, 完整 200 响应写入边缘缓存 (86400s), 重复下载直接命中边缘
// - Range 断点续传请求直接回源, 不缓存

const ORIGIN = "https://release.dianetwork.top";
const CACHE_TTL = 86400;
// 更新 R2 上的同名文件后把这个值 +1 再重新部署, 边缘缓存立即失效
const CACHE_VERSION = 2;

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const originUrl = ORIGIN + url.pathname + url.search;

    if (request.method !== "GET" || request.headers.get("range")) {
      return fetch(originUrl, request);
    }

    const cache = caches.default;
    const cacheKey = new Request(`${url.origin}${url.pathname}?cachev=${CACHE_VERSION}`);
    const cached = await cache.match(cacheKey);
    if (cached) {
      return cached;
    }

    const res = await fetch(originUrl, request);
    if (res.status === 200) {
      await cache.put(cacheKey, res.clone());
      const out = new Response(res.body, res);
      out.headers.set("Cache-Control", `public, max-age=${CACHE_TTL}`);
      return out;
    }
    return res;
  },
};
