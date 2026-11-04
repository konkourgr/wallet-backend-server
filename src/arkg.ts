import { p256 } from "@noble/curves/nist.js";
import { hash_to_field } from "@noble/curves/abstract/hash-to-curve.js";
import { sha256 } from "@noble/hashes/sha256";
import { hkdf } from "@noble/hashes/hkdf";
import { hmac } from "@noble/hashes/hmac";
import { Decoder } from "cbor-x";
const toBase64Url = (value: Uint8Array) =>
	Buffer.from(value).toString("base64url");

const decoder = new Decoder({ mapsAsObjects: false });
const text = (value: string) => new TextEncoder().encode(value);
const concat = (...values: Uint8Array[]) =>
	Uint8Array.from(values.flatMap((v) => Array.from(v)));

function scalar(ikm: Uint8Array, dst: Uint8Array): bigint {
	return hash_to_field(ikm, 1, {
		DST: dst,
		p: p256.CURVE.n,
		m: 1,
		k: 128,
		expand: "xmd",
		hash: sha256,
	})[0][0];
}

function cosePoint(key: unknown): Uint8Array {
	if (
		!(key instanceof Map) ||
		key.get(1) !== 2 ||
		key.get(-1) !== 1 ||
		key.has(-4)
	) {
		throw new Error("Expected a public P-256 COSE key");
	}
	const x: unknown = key.get(-2);
	const y: unknown = key.get(-3);
	if (!(x instanceof Uint8Array) || x.length !== 32)
		throw new Error("Invalid P-256 x coordinate");
	let encoded: Uint8Array;
	if (typeof y === "boolean") {
		encoded = concat(Uint8Array.of(y ? 3 : 2), x);
	} else if (y instanceof Uint8Array && y.length === 32) {
		encoded = concat(Uint8Array.of(4), x, y);
	} else {
		throw new Error("Invalid P-256 y coordinate");
	}
	const point = p256.Point.fromHex(encoded);
	point.assertValidity();
	return point.toBytes(false);
}

export function decodeArkgPublicSeed(publicSeed: Uint8Array): {
	blinding: Uint8Array;
	kem: Uint8Array;
} {
	const seed: unknown = decoder.decode(publicSeed);
	// -65700 is the v4 preview's ARKG-P256 identifier. Do not accept
	// other draft identifiers silently: firmware compatibility is required.
	if (
		!(seed instanceof Map) ||
		seed.get(1) !== -65537 ||
		seed.get(3) !== -65700 ||
		(seed.has(-3) && seed.get(-3) !== -9 && seed.get(-3) !== -7)
	) {
		throw new Error(
			"Unsupported ARKG public seed (expected previewSign v4 ARKG-P256)",
		);
	}
	return { blinding: cosePoint(seed.get(-1)), kem: cosePoint(seed.get(-2)) };
}

/** ARKG-P256, July 2026 draft, sections 2.3, 3.1–3.3 and 4.1.
 * Only public derivation is implemented. No holder signing private key is created.
 */
export function deriveArkgPublicKey(
	publicSeed: Uint8Array,
	ikm: Uint8Array,
	context: Uint8Array,
) {
	if (ikm.length < 32)
		throw new Error("ARKG derivation requires at least 32 bytes of entropy");
	if (context.length > 64) throw new Error("ARKG context exceeds 64 bytes");
	const seed = decodeArkgPublicSeed(publicSeed);
	const ctx = concat(Uint8Array.of(context.length), context);
	const ctxKem = concat(text("ARKG-Derive-Key-KEM."), ctx);
	const ephemeral = scalar(ikm, text("ARKG-KEM-ECDH-KG.ARKG-ECDH.ARKG-P256"));
	if (ephemeral === BigInt(0))
		throw new Error("ARKG produced a zero scalar; retry with fresh entropy");
	const ciphertext = p256.Point.BASE.multiply(ephemeral).toBytes(false);
	const shared = p256.getSharedSecret(ephemeral, seed.kem, false).slice(1, 33);
	const macKey = hkdf(
		sha256,
		shared,
		undefined,
		concat(text("ARKG-KEM-HMAC-mac.ARKG-ECDH.ARKG-P256"), ctxKem),
		32,
	);
	const tag = hmac(sha256, macKey, ciphertext).slice(0, 16);
	const ikmTau = hkdf(
		sha256,
		shared,
		undefined,
		concat(text("ARKG-KEM-HMAC-shared.ARKG-ECDH.ARKG-P256"), ctxKem),
		32,
	);
	const tau = scalar(
		ikmTau,
		concat(text("ARKG-BL-EC.ARKG-P256ARKG-Derive-Key-BL."), ctx),
	);
	const point = p256.Point.fromHex(seed.blinding).add(
		p256.Point.BASE.multiplyUnsafe(tau),
	);
	point.assertValidity();
	const publicKey = point.toBytes(false);
	return {
		publicKeyJwk: {
			kty: "EC",
			crv: "P-256",
			alg: "ES256",
			x: toBase64Url(publicKey.slice(1, 33)),
			y: toBase64Url(publicKey.slice(33)),
		},
		ticket: concat(tag, ciphertext),
	};
}
