import * as crypto from 'crypto';
import { promisify } from 'util';

import { CryptoCipher, CipherMode, HashAlgorithm } from './types';

const randomBytes = promisify(crypto.randomBytes);

export const ACCESS = Symbol('access');
export class Key {
	#key: crypto.KeyObject;
	constructor(access: typeof ACCESS, key: crypto.KeyObject) {
		if (access !== ACCESS) throw new TypeError('access denied');
		this.#key = key;
	}
	extract(access: typeof ACCESS) {
		if (access !== ACCESS) throw new TypeError('access denied');
		return this.#key;
	}
}
export const HEADER = Buffer.from('%RSA');
export function cipherChoice(input: CryptoCipher = 'aes256', mode: CipherMode = 'cbc'): string {
	let cipher: string = input;
	if (cipher === 'blowfish') cipher = 'bf';
	if (cipher === 'des3') cipher = 'des-ede3';
	cipher = cipher.replace(/(128|192|256)$/, '-$1');
	return `${cipher}-${mode}`;
}

export async function hash(
	data: string | Uint8Array | Iterable<string | Uint8Array> | AsyncIterable<string | Uint8Array>,
	algorithm: HashAlgorithm = 'sha512',
): Promise<Uint8Array> {
	const hash = crypto.createHash(algorithm);
	if ('string' === typeof data) data = [data];
	if (data instanceof Uint8Array) data = [data];
	for await (const chunk of data) hash.update(chunk);
	return hash.digest();
}

export async function random(length: number): Promise<Uint8Array> {
	return await randomBytes(length);
}
