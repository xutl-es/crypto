# @xutl/defer

One [eXtremely Useful Tool Library](https://xutl.es) to Simplfy working with crypto in node.

## Install

```bash
npm install --save-dev @xutl/crypto
```

## Usage

```typescript
import { hash, random, SecretKey, PrivateKey } from '@xutl/crypto';

// data can be string | Uint8Array | Iterable<Uint8Array> | AsyncIterable<Uint8Array>
const sha1 = await hash(data, 'sha1');
const sha256 = await hash(data, 'sha256');
const sha512 = await hash(data, 'sha512');

const secret = SecretKey.createRandom(2048);
for await (const chunk of await secret.encrypt('aes256', data, await random(16) /* needs to be a iv */, 'cbc')) {
	write_encrypted(chunk);
}
for await (const chunk of await secret.decrypt('aes256', data, await random(16) /* needs to be the iv */, 'cbc')) {
	write_decrypted(chunk);
}

const pkey = await PrivateKey.createRSA(2048);
const sig = await pkey.sign('hallo');
if (pkey.public.verify(sig, 'hallo')) console.log('verified');

for await (const chunk of await pkey.encipher(data)) {
	write_encrypted(chunk);
}

for await (const chunk of await pkey.private.decipher(data)) {
	write_decrypted(chunk);
}

const bytes = await secret.export();
await pkey.der();
await pkey.pem();
await pkey.public.der();
await pkey.public.pem();

const pubkey = await PublicKey.fromPEM(pemstring);
const pubkey = await PublicKey.fromDER(derbuffer);
```

- plus there's Diffie-Hellman exchanges (both regular & EC)
- plus there's DSA, EC, ...
- use typescript to get full signatures

## License

Copyright 2019,2020 xutl.es

Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
