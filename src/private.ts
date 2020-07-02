import * as crypto from 'crypto';
import { promisify } from 'util';

import { defer } from '@xutl/defer';
import { queue } from '@xutl/queue';

import { ACCESS, Key, cipherChoice, HEADER, hash } from './basic';
import { PublicKey } from './public';
import { CryptoCipher, CipherMode, Signatures, KeySize, CryptoECCurve } from './types';
import { SecretKey } from './secret';

const generateKeyPair = promisify(crypto.generateKeyPair);

export class PrivateKey extends Key {
	#public?: PublicKey;
	constructor(access: typeof ACCESS, key: crypto.KeyObject, pub?: crypto.KeyObject) {
		super(access, key);
		if (pub) {
			this.#public = new PublicKey(access, pub);
		}
	}
	get algorithm(): string | undefined {
		return this.extract(ACCESS).asymmetricKeyType;
	}

	get public() {
		if (this.#public) return this.#public;
		const key = crypto.createPublicKey(this.extract(ACCESS));
		this.#public = new PublicKey(ACCESS, key);
		return this.#public;
	}
	pem(
		type: 'pkcs1' | 'pkcs8' | 'sec1' = 'pkcs8',
		passcode?: string | Uint8Array,
		algorithm?: CryptoCipher,
		mode?: CipherMode,
	): string {
		const passphrase = passcode && Buffer.from(passcode);
		const cipher = passphrase && cipherChoice(algorithm, mode);
		return this.extract(ACCESS).export({
			format: 'pem',
			type,
			passphrase,
			cipher,
		}) as string;
	}
	der(
		type: 'pkcs1' | 'pkcs8' | 'sec1' = 'pkcs8',
		passcode?: string | Uint8Array,
		algorithm?: CryptoCipher,
		mode?: CipherMode,
	): Uint8Array {
		const passphrase = passcode && Buffer.from(passcode);
		const cipher = passphrase && cipherChoice(algorithm, mode);
		return this.extract(ACCESS).export({
			format: 'der',
			type,
			passphrase,
			cipher,
		});
	}
	encrypt(data: Uint8Array): Uint8Array {
		const key = this.extract(ACCESS);
		if (key.asymmetricKeyType === 'dsa') {
			throw new Error('cannot encrypt/decrypt with DSA');
		}
		return crypto.privateEncrypt(key, data);
	}
	decrypt(data: Uint8Array): Uint8Array {
		const key = this.extract(ACCESS);
		if (key.asymmetricKeyType === 'dsa') {
			throw new Error('cannot encrypt/decrypt with DSA');
		}
		return crypto.privateDecrypt(key, data);
	}
	async decipher(input: Iterable<Uint8Array> | AsyncIterable<Uint8Array>): Promise<AsyncIterableIterator<Uint8Array>> {
		const gate = defer<{
			secret: SecretKey;
			iv: Uint8Array;
			data: AsyncIterable<Uint8Array>;
			cipher: CryptoCipher;
			mode: CipherMode;
		}>();
		(async (data: Iterable<Uint8Array> | AsyncIterable<Uint8Array>) => {
			const crypted = queue<Uint8Array>();
			let secret: SecretKey;
			let iv: Uint8Array = Buffer.alloc(0);
			let cipher: CryptoCipher;
			let mode: CipherMode;
			let buffer: Uint8Array = Buffer.alloc(0);

			let mark = 0;

			const iter = (
				(data as Iterable<Uint8Array>)[Symbol.iterator] || (data as AsyncIterable<Uint8Array>)[Symbol.asyncIterator]
			).call(data) as Iterator<Uint8Array> | AsyncIterator<Uint8Array>;

			while (buffer.length < HEADER.length) {
				const { value, done } = await iter.next();
				if (done) throw new Error('unexpected end of data');
				buffer = Buffer.concat([buffer, value]);
			}

			if (Buffer.from(buffer.slice(0, HEADER.length)).toString('hex') !== HEADER.toString('hex')) {
				throw new Error('unexpected data (header signature)');
			}
			buffer = buffer.slice(HEADER.length);

			while (buffer.length < 6) {
				const { value, done } = await iter.next();
				if (done) throw new Error('unexpected end of data');
				buffer = Buffer.concat([buffer, value]);
			}
			do {
				let size = 0;
				const buf = Buffer.from(buffer.slice(0, 8));
				buffer = buffer.slice(6);

				size = buf.readUInt8(0);
				while (buffer.length < size) {
					const { value, done } = await iter.next();
					if (done) throw new Error('unexpected end of data');
					buffer = Buffer.concat([buffer, value]);
				}

				const prn = Buffer.from(await hash(this.public.der(), 'sha1'));
				const enc = Buffer.from(buffer.slice(0, size));
				if (prn.length !== enc.length || prn.toString('hex') !== enc.toString('hex')) {
					throw new Error('not enciphered for me');
				}
				buffer = buffer.slice(size);

				size = buf.readUInt16BE(1);
				while (buffer.length < size) {
					const { value, done } = await iter.next();
					if (done) throw new Error('unexpected end of data');
					buffer = Buffer.concat([buffer, value]);
				}
				secret = SecretKey.fromBytes(this.decrypt(buffer.slice(0, size)));
				buffer = buffer.slice(size);

				size = buf.readUInt8(3);
				while (buffer.length < size) {
					const { value, done } = await iter.next();
					if (done) throw new Error('unexpected end of data');
					buffer = Buffer.concat([buffer, value]);
				}
				iv = buffer.slice(0, size);
				buffer = buffer.slice(size);

				size = buf.readUInt8(4);
				while (buffer.length < size) {
					const { value, done } = await iter.next();
					if (done) throw new Error('unexpected end of data');
					buffer = Buffer.concat([buffer, value]);
				}
				cipher = Buffer.from(buffer.slice(0, size)).toString('ascii') as CryptoCipher;
				buffer = buffer.slice(size);

				size = buf.readUInt8(5);
				while (buffer.length < size) {
					const { value, done } = await iter.next();
					if (done) throw new Error('unexpected end of data');
					buffer = Buffer.concat([buffer, value]);
				}
				mode = Buffer.from(buffer.slice(0, size)).toString('ascii') as CipherMode;
				buffer = buffer.slice(size);
			} while (0);

			gate.resolve({
				secret,
				iv,
				data: crypted,
				cipher,
				mode,
			});

			try {
				let value: Uint8Array | null = null;
				let done: boolean | undefined = false;
				crypted.push(buffer);
				while (!done) {
					({ value, done } = await iter.next());
					if (value && !done) crypted.push(value);
				}
			} catch (e) {
				crypted.error(e);
			} finally {
				crypted.done();
			}
		})(input);

		const { secret, iv, data, cipher, mode } = await gate;
		return secret.decrypt(cipher, data, iv, mode);
	}

	async sign(
		data: Uint8Array | Iterable<Uint8Array> | AsyncIterable<Uint8Array>,
		algorithm: Signatures = 'RSA-SHA256',
	): Promise<Uint8Array> {
		const key = this.extract(ACCESS);
		if (data instanceof Uint8Array) data = [data];
		const sign = crypto.createSign(algorithm);
		for await (const chunk of data) sign.update(chunk);
		return sign.sign(key);
	}
	static fromPEM(key: string, passcode?: string | Uint8Array): PrivateKey {
		const passphrase = passcode && Buffer.from(passcode);
		const keyobject = crypto.createPrivateKey({
			key,
			format: 'pem',
			passphrase,
		});
		return new PrivateKey(ACCESS, keyobject);
	}
	static fromDER(
		key: Uint8Array,
		passcode?: string | Uint8Array | undefined,
		type: 'pkcs1' | 'pkcs8' | 'sec1' = 'pkcs8',
	): PrivateKey {
		const passphrase = passcode && Buffer.from(passcode);
		const keyobject = crypto.createPrivateKey({
			key: Buffer.from(key),
			format: 'der',
			type,
			passphrase,
		});
		return new PrivateKey(ACCESS, keyobject);
	}

	static async createRSA(keysize: KeySize = 4096, options?: crypto.RSAKeyPairKeyObjectOptions) {
		const resolved = Object.assign({}, options ?? {}, {
			modulusLength: keysize,
			publicKeyEncoding: null,
			privateKeyEncoding: null,
		});
		const pair: {
			publicKey: crypto.KeyObject;
			privateKey: crypto.KeyObject;
		} = await generateKeyPair('rsa', (resolved as any) as crypto.RSAKeyPairKeyObjectOptions);
		return new PrivateKey(ACCESS, pair.privateKey, pair.publicKey);
	}
	static async createDSA(keysize: KeySize = 4096, options?: crypto.DSAKeyPairKeyObjectOptions) {
		const resolved = Object.assign({}, options ?? {}, {
			modulusLength: keysize,
			publicKeyEncoding: null,
			privateKeyEncoding: null,
		});
		const pair: {
			publicKey: crypto.KeyObject;
			privateKey: crypto.KeyObject;
		} = await generateKeyPair('dsa', (resolved as any) as crypto.DSAKeyPairKeyObjectOptions);
		return new PrivateKey(ACCESS, pair.privateKey, pair.publicKey);
	}
	static async createEC(curve: CryptoECCurve, options?: crypto.ECKeyPairKeyObjectOptions) {
		const resolved = Object.assign({}, options ?? {}, {
			namedCurve: curve,
			publicKeyEncoding: null,
			privateKeyEncoding: null,
		});
		const pair: {
			publicKey: crypto.KeyObject;
			privateKey: crypto.KeyObject;
		} = await generateKeyPair('ec', (resolved as any) as crypto.ECKeyPairKeyObjectOptions);
		return new PrivateKey(ACCESS, pair.privateKey, pair.publicKey);
	}
	static async createED25519() {
		const pair: {
			publicKey: crypto.KeyObject;
			privateKey: crypto.KeyObject;
		} = await generateKeyPair(('ed25519' as any) as 'rsa', {} as crypto.RSAKeyPairKeyObjectOptions);
		return new PrivateKey(ACCESS, pair.privateKey, pair.publicKey);
	}
	static async createED448() {
		const pair: {
			publicKey: crypto.KeyObject;
			privateKey: crypto.KeyObject;
		} = await generateKeyPair(('ed448' as any) as 'rsa', {} as crypto.RSAKeyPairKeyObjectOptions);
		return new PrivateKey(ACCESS, pair.privateKey, pair.publicKey);
	}
	static async createX25519() {
		const pair: {
			publicKey: crypto.KeyObject;
			privateKey: crypto.KeyObject;
		} = await generateKeyPair(('x25519' as any) as 'rsa', {} as crypto.RSAKeyPairKeyObjectOptions);
		return new PrivateKey(ACCESS, pair.privateKey, pair.publicKey);
	}

	static get curves() {
		return crypto.getCurves().filter((c) => !/^Oakley-/.test(c)) as CryptoECCurve[];
	}
}
