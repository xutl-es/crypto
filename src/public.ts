import * as crypto from 'crypto';
import { promisify } from 'util';

import { ACCESS, Key, HEADER, hash } from './basic';
import { CryptoCipher, CipherMode, Signatures } from './types';
import { SecretKey } from './secret';
import { queue } from '@xutl/queue';

const randomBytes = promisify(crypto.randomBytes);

export class PublicKey extends Key {
	get algorithm(): string | undefined {
		return this.extract(ACCESS).asymmetricKeyType;
	}
	async fingerprint() {
		const bits: string[] = [];
		for (const byte of await hash(this.der(), 'sha1')) {
			bits.push(byte.toString(16).toUpperCase());
		}
		return bits.join(':');
	}
	pem(type: 'pkcs1' | 'spki' = 'spki'): string {
		return this.extract(ACCESS).export({ format: 'pem', type }) as string;
	}
	der(type: 'pkcs1' | 'spki' = 'spki'): Uint8Array {
		return this.extract(ACCESS).export({ format: 'der', type });
	}
	encrypt(data: Uint8Array): Uint8Array {
		const key = this.extract(ACCESS);
		if (key.asymmetricKeyType === 'dsa') {
			throw new Error('cannot encrypt/decrypt with DSA');
		}
		return crypto.publicEncrypt(key, data);
	}
	decrypt(data: Uint8Array): Uint8Array {
		const key = this.extract(ACCESS);
		if (key.asymmetricKeyType === 'dsa') {
			throw new Error('cannot encrypt/decrypt with DSA');
		}
		return crypto.publicDecrypt(key, data);
	}

	async encipher(
		data: Iterable<Uint8Array> | AsyncIterable<Uint8Array>,
		cipher: CryptoCipher = 'aes256',
		mode: CipherMode = 'cbc',
	): Promise<AsyncIterableIterator<Uint8Array>> {
		const secret = await SecretKey.createRandom(256);

		const print = await hash(this.der(), 'sha1');
		const secrt = this.encrypt(secret.export());
		const iv = await randomBytes(16);

		const result = queue<Uint8Array>();
		result.push(HEADER);

		const header = Buffer.alloc(6, 0);
		header.writeUInt8(print.length, 0);
		header.writeUInt16BE(secrt.length, 1);
		header.writeUInt8(iv.length, 3);
		header.writeUInt8(Buffer.byteLength(cipher, 'ascii'), 4);
		header.writeUInt8(Buffer.byteLength(mode, 'ascii'), 5);

		result.push(header);

		result.push(print);
		result.push(secrt);
		result.push(iv);
		result.push(Buffer.from(cipher, 'ascii'));
		result.push(Buffer.from(mode, 'ascii'));

		(async function (data: AsyncIterable<Uint8Array>) {
			for await (const chunk of data) {
				result.push(chunk);
			}
		})(await secret.encrypt('aes256', data, iv, 'cbc')).then(
			() => result.done(),
			(e) => result.error(e),
		);

		return result;
	}

	async verify(
		signature: Uint8Array,
		data: Uint8Array | Iterable<Uint8Array> | AsyncIterable<Uint8Array>,
		algorithm: Signatures = 'RSA-SHA256',
	) {
		const key = this.extract(ACCESS);
		if (data instanceof Uint8Array) data = [data];
		const verify = crypto.createVerify(algorithm);
		for await (const chunk of data) verify.update(chunk);
		return verify.verify(key, signature);
	}

	static fromPEM(key: string): PublicKey {
		const keyobject = crypto.createPublicKey({
			key,
			format: 'pem',
		});
		return new PublicKey(ACCESS, keyobject);
	}
	static fromDER(key: Uint8Array, type: 'pkcs1' | 'spki' = 'spki'): PublicKey {
		const keyobject = crypto.createPublicKey({
			key: Buffer.from(key),
			format: 'der',
			type,
		});
		return new PublicKey(ACCESS, keyobject);
	}
}
