import { describe, it } from '@xutl/test';
import assert from 'assert';

import { PrivateKey, random } from '../';

describe('public key', () => {
	describe('rsa', () => {
		const keyPromise = PrivateKey.createRSA(4096);
		const data = random(256) as Promise<Buffer>;
		const huge = random(8192) as Promise<Buffer>;
		it('can private encrypt/decrypt', async () => {
			const keyPromise = PrivateKey.createRSA(4096);
			const key = await keyPromise;
			const crypttext = await key.encrypt(await data);
			const plaintext = (await key.public.decrypt(crypttext)) as Buffer;
			assert.equal(plaintext.toString('hex'), (await data).toString('hex'));
		});
		it('can public encrypt/decrypt', async () => {
			const key = await keyPromise;
			const crypttext = await key.public.encrypt(await data);
			const plaintext = (await key.decrypt(crypttext)) as Buffer;
			assert.equal(plaintext.toString('hex'), (await data).toString('hex'));
		});
		it('can encipher/decipher', async () => {
			const key = await keyPromise;
			const expected = await huge;
			const enciphered = await collect(await key.public.encipher([expected]));
			const deciphered = await collect(await key.decipher([enciphered]));

			assert.equal(deciphered.toString('hex'), expected.toString('hex'));
		});
		it('can sign/verify', async () => {
			const key = await keyPromise;
			const signature = await key.sign(await data);
			const verified = await key.public.verify(signature, await data);
			assert(verified);
		});
	});
	describe('dsa', () => {
		const keyPromise = PrivateKey.createDSA(1024);
		const data = random(4096) as Promise<Buffer>;
		it('can sign/verify', async () => {
			const key = await keyPromise;
			const signature = await key.sign(await data);
			const verified = await key.public.verify(signature, await data);
			assert(verified);
		});
	});
	describe('ec', () => {
		const data = random(256) as Promise<Buffer>;
		for (const curve of PrivateKey.curves) {
			it(`${curve} can sign/verify`, async () => {
				const key = await PrivateKey.createEC(curve);
				const signature = await key.sign(await data);
				const verified = await key.public.verify(signature, await data);
				assert(verified);
			});
		}
	});
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
