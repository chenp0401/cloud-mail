import app from '../hono/hono';
import { dbInit } from '../init/init';

// 数据库初始化入口。
// 安全加固：原先用 GET /init/:secret 传密钥，密钥会落在 URL 里 —— 进入 Cloudflare 访问日志、
// 反向代理日志和浏览器历史，且可被链接预取意外触发。现改为 POST + 请求头传递。
app.post('/init', (c) => {
	return dbInit.init(c, c.req.header('X-Init-Secret'));
})

// 兼容旧的路径参数写法，但同样只接受 POST（不再暴露 GET）。
app.post('/init/:secret', (c) => {
	return dbInit.init(c, c.req.param('secret'));
})
