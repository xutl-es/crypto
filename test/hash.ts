import { describe, it, before } from '@xutl/test';
import assert from 'assert';

import { hash, random } from '../';

describe('hash', () => {
	let data: Buffer;
	before(async () => {
		data = (await random(16)) as Buffer;
	});
	it('sha1(bytes) hashes to 20 bytes', async () => {
		const res = await hash(data, 'sha1');
		assert.equal(res.length, 20);
	});
	it('sha256(bytes) hashes to 32 bytes', async () => {
		const res = await hash(data, 'sha256');
		assert.equal(res.length, 32);
	});
	it('sha512(bytes) hashes to 64 bytes', async () => {
		const res = await hash(data, 'sha512');
		assert.equal(res.length, 64);
	});
	it('sha1(string) hashes to 20 bytes', async () => {
		const res = await hash(data.toString('hex'), 'sha1');
		assert.equal(res.length, 20);
	});
	it('sha256(string) hashes to 32 bytes', async () => {
		const res = await hash(data.toString('hex'), 'sha256');
		assert.equal(res.length, 32);
	});
	it('sha512(string) hashes to 64 bytes', async () => {
		const res = await hash(data.toString('hex'), 'sha512');
		assert.equal(res.length, 64);
	});
	it('sha1(iterable) hashes to 20 bytes', async () => {
		const res = await hash([data], 'sha1');
		assert.equal(res.length, 20);
	});
	it('sha256(iterable) hashes to 32 bytes', async () => {
		const res = await hash([data], 'sha256');
		assert.equal(res.length, 32);
	});
	it('sha512(iterable) hashes to 64 bytes', async () => {
		const res = await hash([data], 'sha512');
		assert.equal(res.length, 64);
	});
});
