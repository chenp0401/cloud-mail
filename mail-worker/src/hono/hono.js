import { Hono } from 'hono';
const app = new Hono();

import result from '../model/result';
import { cors } from 'hono/cors';

// 安全加固：原为 cors()（等价 Access-Control-Allow-Origin: *）。
// 收敛为「仅放行同源」—— 服务端调用不带 Origin，不受影响；公网任意站点不再拿到 CORS 头。
app.use('*', cors({
	origin: (origin, c) => {
		if (!origin) return null;
		try {
			const o = new URL(origin);
			const host = c.req.header('host') || '';
			return o.host === host ? origin : null;
		} catch (e) {
			return null;
		}
	},
	allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
	allowHeaders: ['Content-Type', 'Authorization'],
	credentials: true
}));

app.onError((err, c) => {
	if (err.name === 'BizError') {
		console.log(err.message);
	} else {
		console.error(err);
	}

	if (err.message === `Cannot read properties of undefined (reading 'get')`) {
		return c.json(result.fail('KV数据库未绑定<br/>KV database not bound',502));
	}

	if (err.message === `Cannot read properties of undefined (reading 'put')`) {
		return c.json(result.fail('KV数据库未绑定<br/>KV database not bound',502));
	}

	if (err.message === `Cannot read properties of undefined (reading 'prepare')`) {
		return c.json(result.fail('D1数据库未绑定<br/>D1 database not bound',502));
	}

	if (err.message?.includes('D1_ERROR: no such column')) {
		return c.json(result.fail('请按照文档更新数据库<br/>Please update the database as documented',502));
	}

	return c.json(result.fail(err.message, err.code));
});

export default app;


