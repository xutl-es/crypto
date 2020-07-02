import * as crypto from 'crypto';
import { ACCESS } from './basic';
import { SecretKey } from './secret';
import { KeySize } from './types';

export interface DiffieHellmanExchange {
	public: string;
	prime: string;
	generator: string;
}
export class DH {
	#dh: crypto.DiffieHellman;
	constructor(access: typeof ACCESS, dh: crypto.DiffieHellman) {
		if (access !== ACCESS) throw new TypeError('access denied');
		this.#dh = dh;
	}
	exchange(): DiffieHellmanExchange {
		const publicKey = this.#dh.getPublicKey('hex');
		const prime = this.#dh.getPrime('hex');
		const generator = this.#dh.getGenerator('hex');
		return { public: publicKey, prime, generator };
	}
	secret(info: DiffieHellmanExchange): SecretKey {
		const dh = this.#dh;
		const key = crypto.createSecretKey(dh.computeSecret(info.public, 'hex'));
		return new SecretKey(ACCESS, key);
	}
	static create(info: KeySize | DiffieHellmanExchange) {
		if ('number' === typeof info) {
			const dh = crypto.createDiffieHellman(info);
			dh.generateKeys();
			return new DH(ACCESS, dh);
		} else {
			const dh = crypto.createDiffieHellman(
				/* @ts-ignore */
				Buffer.from(info.prime, 'hex'),
				Buffer.from(info.generator, 'hex'),
			);
			dh.generateKeys();
			return new DH(ACCESS, dh);
		}
	}
	static secret(info: DiffieHellmanExchange): { secret: SecretKey; exchange: DiffieHellmanExchange } {
		const dh = crypto.createDiffieHellman(
			/* @ts-ignore */
			Buffer.from(info.prime, 'hex'),
			Buffer.from(info.generator, 'hex'),
		);
		dh.generateKeys();
		const key = crypto.createSecretKey(dh.computeSecret(info.public, 'hex'));
		const secret = new SecretKey(ACCESS, key);
		const exchange = { ...info, public: dh.getPublicKey('hex') };
		return { secret, exchange };
	}
}
