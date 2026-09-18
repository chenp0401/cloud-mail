import resendService from '../service/resend-service';
import app from '../hono/hono';

// 安全加固：原先该端点未鉴权即可调用并写入 D1。
// 现在必须先通过 Svix 签名校验（密钥存在 setting.resend_webhook_secret），
// 未配置密钥时一律拒绝 —— 相当于默认关闭。
app.post('/webhooks', async (c) => {
	try {
		// 签名是对「原始请求体字节」计算的，不能先解析成 JSON 再验签
		const rawBody = await c.req.text();
		await resendService.webhooks(c, rawBody);
		return c.text('success', 200)
	} catch (e) {
		const code = (e && e.name === 'BizError' && e.code) ? e.code : 500;
		return c.text(e.message, code)
	}
})
