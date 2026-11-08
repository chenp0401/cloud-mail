import emailService from './email-service';
import { emailConst } from '../const/entity-const';
import BizError from '../error/biz-error';
import settingService from './setting-service';

// ---------------- Svix 签名校验（Resend 的 webhook 走 Svix 协议）----------------

function b64ToBytes(b64) {
	const bin = atob(b64);
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}

function bytesToB64(buf) {
	const arr = new Uint8Array(buf);
	let s = '';
	for (let i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
	return btoa(s);
}

async function hmacB64(keyBytes, message) {
	const key = await crypto.subtle.importKey(
		'raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
	);
	const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
	return bytesToB64(sig);
}

// 定长常量时间比较，避免时序侧信道
function timingSafeEqual(a, b) {
	if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
	return diff === 0;
}

const resendService = {

	async verifySvix(c, rawBody) {

		const setting = await settingService.query(c);
		const secret = setting.resendWebhookSecret;

		// 未配置签名密钥时一律拒绝。这样该端点默认是关闭的，
		// 只有显式配置了 Resend webhook 密钥之后才会开始接受投递。
		if (!secret) {
			throw new BizError('webhook 未配置签名密钥，已拒绝', 403);
		}

		const id = c.req.header('svix-id');
		const ts = c.req.header('svix-timestamp');
		const sigHeader = c.req.header('svix-signature');

		if (!id || !ts || !sigHeader) {
			throw new BizError('缺少 Svix 签名头', 401);
		}

		// 防重放：时间戳与当前时间偏差不得超过 5 分钟
		const now = Math.floor(Date.now() / 1000);
		if (!Number.isFinite(Number(ts)) || Math.abs(now - Number(ts)) > 300) {
			throw new BizError('Svix 时间戳超出容差', 401);
		}

		const keyBytes = b64ToBytes(String(secret).replace(/^whsec_/, ''));
		const expected = await hmacB64(keyBytes, `${id}.${ts}.${rawBody}`);

		const ok = String(sigHeader).split(' ').some(part => {
			const idx = part.indexOf(',');
			if (idx === -1) return false;
			return part.slice(0, idx) === 'v1' && timingSafeEqual(part.slice(idx + 1), expected);
		});

		if (!ok) {
			throw new BizError('Svix 签名校验失败', 401);
		}
	},

	async webhooks(c, rawBody) {

		await this.verifySvix(c, rawBody);

		let body;
		try {
			body = JSON.parse(rawBody);
		} catch (e) {
			throw new BizError('webhook 载荷不是合法 JSON', 400);
		}

		if (!body || !body.type || !body.data || !body.data.email_id) {
			throw new BizError('webhook 载荷缺少必要字段', 400);
		}

		const params = {
			resendEmailId: body.data.email_id,
			status: emailConst.status.SENT
		}

		if (body.type === 'email.delivered') {
			params.status = emailConst.status.DELIVERED
			params.message = null
		}

		if (body.type === 'email.complained') {
			params.status = emailConst.status.COMPLAINED
			params.message = null
		}

		if (body.type === 'email.bounced') {
			let bounce = body.data.bounce
			bounce = JSON.stringify(bounce);
			params.status = emailConst.status.BOUNCED
			params.message = bounce
		}

		if (body.type === 'email.delivery_delayed') {
			params.status = emailConst.status.DELAYED
			params.message = null
		}

		if (body.type === 'email.failed') {
			params.status = emailConst.status.FAILED
			params.message = body.data.failed.reason
		}

		const emailRow = await emailService.updateEmailStatus(c, params)

		if (!emailRow) {
			// 未知邮件事件（如历史数据、重复投递、测试事件）：记录日志后正常返回，
			// 避免 Resend 因连续收到 500 而熔断关闭 Webhook
			console.warn(`resend webhook: unknown email_id ${params.resendEmailId}, type ${body.type}`);
			return;
		}

	}
}

export default resendService
