import * as crypto from 'crypto';
import { ACCESS } from './basic';
import { SecretKey } from './secret';
import { CryptoECCurve } from './types';

export class ECDH {
	#dh: crypto.ECDH;
	constructor(access: typeof ACCESS, dh: crypto.ECDH) {
		if (access !== ACCESS) throw new TypeError('access denied');
		this.#dh = dh;
	}
	public() {
		return this.#dh.getPublicKey();
	}
	compute(otherKey: string) {
		const key = crypto.createSecretKey(this.#dh.computeSecret(otherKey, 'hex'));
		return new SecretKey(ACCESS, key);
	}
	static create(curve: CryptoECCurve) {
		const dh = crypto.createECDH(curve);
		dh.generateKeys();
		return new ECDH(ACCESS, dh);
	}
}
