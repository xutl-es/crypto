import { hash, random } from './basic';
import { SecretKey } from './secret';
import { PrivateKey } from './private';
import { PublicKey } from './public';

export { hash, random, SecretKey, PrivateKey, PublicKey };
const Default = Object.freeze({
	hash,
	random,
	SecretKey,
	PrivateKey,
	PublicKey,
});
export default Default;
