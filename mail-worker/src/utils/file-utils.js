const fileUtils = {
	getExtFileName(filename) {
		try {
			const index = filename.lastIndexOf('.');
			return index !== -1 ? filename.slice(index) : '';
		} catch (e) {
			return ''
		}
	},

	async getBuffHash(buff) {
		const hashBuffer = await crypto.subtle.digest('SHA-256', buff);
		const hashArray = Array.from(new Uint8Array(hashBuffer));
		return hashArray.slice(0, 16).map(b => b.toString(16).padStart(2, '0')).join('');
	},

	// 密钥派生的对象键名。
	// 原来的 getBuffHash 是 SHA-256(内容)：附件 URL 形如 /attachments/<sha256前32位>.bin，
	// 而该路径在 index.js 里是匿名可读的 —— 攻击者只要知道（或猜到）文件内容，
	// 就能自己算出键名直接下载，不需要任何凭证。
	// 改用 HMAC(密钥, 内容) 后：键名仍由内容决定（内容相同的附件依旧去重，不浪费 KV 配额），
	// 但没有密钥的外部方无法从内容反推键名。
	async getSecretHash(buff, secret) {
		const key = await crypto.subtle.importKey(
			'raw',
			new TextEncoder().encode(String(secret || '')),
			{ name: 'HMAC', hash: 'SHA-256' },
			false,
			['sign']
		);
		const sigBuffer = await crypto.subtle.sign('HMAC', key, buff);
		const sigArray = Array.from(new Uint8Array(sigBuffer));
		return sigArray.slice(0, 16).map(b => b.toString(16).padStart(2, '0')).join('');
	},

	base64ToDataStr(base64) {
		return base64.split(',')[1] || base64;
	},

	base64ToUint8Array(base64) {
		const binaryStr = atob(base64);
		const len = binaryStr.length;
		const bytes = new Uint8Array(len);
		for (let i = 0; i < len; i++) {
			bytes[i] = binaryStr.charCodeAt(i);
		}
		return bytes;
	},

	/**
	 * 将 Base64 数据转换为 File 对象（自动识别 MIME 类型和文件扩展名）
	 * @param {string} base64Data 带有 data: 前缀的 base64 数据
	 * @param {string} [customFilename] 可选，传入自定义文件名（不含扩展名）
	 * @returns {File} File 对象
	 */
	base64ToFile(base64Data, customFilename) {
		const match = base64Data.match(/^data:(image|jpeg|video)\/([a-zA-Z0-9.+-]+);base64,/);
		if (!match) {
			throw new Error('Invalid base64 data format');
		}

		const type = match[1]; // image 或 video
		const ext = match[2];  // jpg, png, mp4 等
		const mimeType = `${type}/${ext}`;
		const cleanBase64 = base64Data.replace(/^data:(image|jpeg|video)\/[a-zA-Z0-9.+-]+;base64,/, '');

		const byteCharacters = atob(cleanBase64);
		const byteArrays = [];

		for (let offset = 0; offset < byteCharacters.length; offset += 1024) {
			const slice = byteCharacters.slice(offset, offset + 1024);
			const byteNumbers = new Array(slice.length);
			for (let i = 0; i < slice.length; i++) {
				byteNumbers[i] = slice.charCodeAt(i);
			}
			byteArrays.push(new Uint8Array(byteNumbers));
		}

		const blob = new Blob(byteArrays, { type: mimeType });

		const filename = `${customFilename || `${type}_${Date.now()}`}.${ext}`;
		return new File([blob], filename, { type: mimeType });
	}
};


export default fileUtils;

