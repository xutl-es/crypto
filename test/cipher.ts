import { describe, it } from '@xutl/test';
import assert from 'assert';

import { SecretKey, random } from '../';

describe('cipher', () => {
	for (const cipher of SecretKey.ciphers) {
		it(`cipher ${cipher}`, async () => {
			const expected = (await random(256)) as Buffer;
			const key = await SecretKey.createRandom(SecretKey.keySize(cipher));
			const iv = await SecretKey.iv(cipher);

			const crypttext = await collect(await key.encrypt(cipher, expected, iv));
			const plaintext = await collect(await key.decrypt(cipher, crypttext, iv));
			assert.equal(plaintext.toString('hex'), expected.toString('hex'));
		});
	}
});

async function collect(data: Iterable<Uint8Array> | AsyncIterable<Uint8Array>): Promise<Buffer> {
	const buffers = [];
	let length = 0;
	for await (const chunk of data) {
		buffers.push(chunk);
		length += chunk.length;
	}
	return Buffer.concat(buffers, length);
}
