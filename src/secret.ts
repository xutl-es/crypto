import * as crypto from 'crypto';
import { promisify } from 'util';

import { queue } from '@xutl/queue';

import { ACCESS, Key, cipherChoice } from './basic';
import { CryptoCipher, CipherMode, CipherKeySize, HashAlgorithm, KeySize } from './types';

const randomBytes = promisify(crypto.randomBytes);

export interface SCryptOptions {
	cost?: number;
	blockSize?: number;
	parallelization?: number;
	maxmem?: number;
}

const CIPHERS: CryptoCipher[] = [
	'aes128',
	'aes192',
	'aes256',
	'aria128',
	'aria192',
	'aria256',
	'blowfish',
	'camellia128',
	'camellia192',
	'camellia256',
	'cast',
	'des',
	'des3',
	'idea',
	'rc2',
	'seed',
	'sm4',
];
const CIPHER_KEY: { [name: string]: CipherKeySize } = Object.freeze({
	aes128: 128,
	aes192: 192,
	aes256: 256,
	aria128: 128,
	aria192: 192,
	aria256: 256,
	blowfish: 448,
	camellia128: 128,
	camellia192: 192,
	camellia256: 256,
	cast: 128,
	des: 64,
	des3: 192,
	idea: 128,
	rc2: 256,
	seed: 128,
	sm4: 128,
});
export const CIPHER_IV: { [name: string]: CipherKeySize } = Object.freeze({
	aes128: 128,
	aes192: 128,
	aes256: 128,
	aria128: 128,
	aria192: 128,
	aria256: 128,
	blowfish: 64,
	camellia128: 128,
	camellia192: 128,
	camellia256: 128,
	cast: 64,
	des: 64,
	des3: 64,
	idea: 64,
	rc2: 64,
	seed: 128,
	sm4: 128,
});

export class SecretKey extends Key {
	export(): Uint8Array {
		return this.extract(ACCESS).export();
	}
	async encrypt(
		alhorithm: CryptoCipher,
		data: Uint8Array | Iterable<Uint8Array> | AsyncIterable<Uint8Array>,
		iv: Uint8Array,
		mode?: CipherMode,
	): Promise<AsyncIterableIterator<Uint8Array>> {
		const key = this.extract(ACCESS);
		const cipher = crypto.createCipheriv(cipherChoice(alhorithm, mode), key, iv);
		if (data instanceof Uint8Array) data = [data];

		const code = queue<Uint8Array>();
		(async function (data: AsyncIterable<Uint8Array>) {
			for await (const chunk of data) {
				code.push(cipher.update(chunk));
			}
			code.push(cipher.final());
		})(data as AsyncIterable<Uint8Array>).then(
			() => code.done(),
			(e) => code.error(e),
		);
		return code;
	}
	async decrypt(
		alhorithm: CryptoCipher,
		data: Uint8Array | Iterable<Uint8Array> | AsyncIterable<Uint8Array>,
		iv: Uint8Array,
		mode?: CipherMode,
	): Promise<AsyncIterableIterator<Uint8Array>> {
		const key = this.extract(ACCESS);
		const cipher = crypto.createDecipheriv(cipherChoice(alhorithm, mode), key, iv);
		if (data instanceof Uint8Array) data = [data];

		const code = queue<Uint8Array>();
		(async function (data: AsyncIterable<Uint8Array>) {
			for await (const chunk of data) {
				code.push(cipher.update(chunk));
			}
			code.push(cipher.final());
		})(data as AsyncIterable<Uint8Array>).then(
			() => code.done(),
			(e) => code.error(e),
		);
		return code;
	}
	static fromBytes(keydata: Uint8Array): SecretKey {
		return new SecretKey(ACCESS, crypto.createSecretKey(Buffer.from(keydata)));
	}
	static async createRandom(size: CipherKeySize) {
		const keydata = await randomBytes(size / 8);
		return new SecretKey(ACCESS, crypto.createSecretKey(keydata));
	}
	static async createPBKDF2(
		password: string | Uint8Array,
		salt: string | Uint8Array,
		iterations: number = 10000,
		keylen: CipherKeySize = 256,
		digest: HashAlgorithm = 'sha256',
	) {
		const keydata: Buffer = await new Promise((resolve, reject) => {
			crypto.pbkdf2(password, salt, iterations, keylen, digest, (err, key) => {
				if (err) return reject(err);
				resolve(key);
			});
		});
		return new SecretKey(ACCESS, crypto.createSecretKey(keydata));
	}
	static async createSCRYPT(
		password: string | Uint8Array,
		salt: string | Uint8Array,
		keylen: KeySize = 1024,
		options: crypto.ScryptOptions = {},
	) {
		const keydata: Buffer = await new Promise((resolve, reject) => {
			crypto.scrypt(password, salt, keylen, options, (err, buf) => {
				if (err) return reject(err);
				resolve(buf);
			});
		});
		return new SecretKey(ACCESS, crypto.createSecretKey(keydata));
	}

	static keySize(name: CryptoCipher): CipherKeySize {
		return CIPHER_KEY[name];
	}
	static ivSize(name: CryptoCipher): number {
		return CIPHER_IV[name];
	}
	static iv(name: CryptoCipher): Promise<Uint8Array> {
		return randomBytes(CIPHER_IV[name] / 8);
	}
	static get ciphers(): CryptoCipher[] {
		return CIPHERS;
	}
}
