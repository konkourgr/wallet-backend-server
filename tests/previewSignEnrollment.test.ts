import { strict as assert } from "node:assert";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { p256 } from "@noble/curves/nist.js";
import { hash_to_field } from "@noble/curves/abstract/hash-to-curve.js";
import { sha256 } from "@noble/hashes/sha256";
import { hkdf } from "@noble/hashes/hkdf";
import { Encoder } from "cbor-x";
import { SignJWT } from "jose";
import { deriveArkgPublicKey } from "../src/arkg";
import {
	createEnrollmentProof,
	readEnrollmentProof,
	verifyEnrollmentProofSignature,
	type EnrollmentProof,
} from "../src/previewSignEnrollment";

const vectors = JSON.parse(
	readFileSync(join(__dirname, "arkg.vectors.json"), "utf8"),
) as Record<string, string>[];
const encoder = new Encoder({
	useRecords: false,
	mapsAsObjects: false,
	tagUint8Array: false,
	variableMapSize: true,
});
const text = (value: string) => Buffer.from(value);
const hex = (value: string) => Buffer.from(value, "hex");
export function publicSeed(vector = vectors[0]) {
	const point = (value: string) =>
		new Map<number, unknown>([
			[1, 2],
			[-1, 1],
			[-2, hex(value).subarray(1, 33)],
			[-3, hex(value).subarray(33)],
		]);
	return Buffer.from(
		encoder.encode(
			new Map<number, unknown>([
				[1, -65537],
				[3, -65700],
				[-1, point(vector.pk_bl)],
				[-2, point(vector.pk_kem)],
				[-3, -9],
			]),
		),
	);
}

// Test-only authenticator decapsulation using the published private seed.
export function proofSignature(
	proof: EnrollmentProof,
	format: "der" | "compact" = "der",
) {
	const context = Buffer.from(proof.key.context, "base64url");
	const ctx = Buffer.concat([Buffer.from([context.length]), context]);
	const shared = p256
		.getSharedSecret(
			BigInt(
				"0x74e0a4cd81ca2d24246ff75bfd6d4fb7f9dfc938372627feb2c2348f8b1493b5",
			),
			Buffer.from(proof.key.ticket, "base64url").subarray(16),
			false,
		)
		.slice(1, 33);
	const ikm = hkdf(
		sha256,
		shared,
		undefined,
		Buffer.concat([
			text("ARKG-KEM-HMAC-shared.ARKG-ECDH.ARKG-P256ARKG-Derive-Key-KEM."),
			ctx,
		]),
		32,
	);
	const tau = hash_to_field(ikm, 1, {
		DST: Buffer.concat([text("ARKG-BL-EC.ARKG-P256ARKG-Derive-Key-BL."), ctx]),
		p: p256.CURVE.n,
		m: 1,
		k: 128,
		expand: "xmd",
		hash: sha256,
	})[0][0];
	const privateKey =
		(BigInt(
			"0xd959500a78ccf850ce46c80a8c5043c9a2e33844232b3829df37d05b3069f455",
		) +
			tau) %
		p256.CURVE.n;
	return p256
		.sign(sha256(Buffer.from(proof.data, "base64url")), privateKey, {
			prehash: false,
		})
		.toBytes(format);
}

for (const [index, vector] of vectors.entries()) {
	test(`server ARKG derivation matches published vector ${index + 1}`, () => {
		const result = deriveArkgPublicKey(
			publicSeed(vector),
			hex(vector.ikm),
			text(vector.ctx),
		);
		assert.deepEqual(Buffer.from(result.ticket), hex(vector.kh));
		assert.deepEqual(
			Buffer.concat([
				Buffer.from([4]),
				Buffer.from(result.publicKeyJwk.x, "base64url"),
				Buffer.from(result.publicKeyJwk.y, "base64url"),
			]),
			hex(vector.pk_prime),
		);
	});
}

const registration = {
	id: "seed-1",
	userUuid: "alice",
	credentialId: "Y3JlZA",
	webauthnCredentialId: "shared-passkey-row",
	keyHandle: "aGFuZGxl",
	publicSeed: publicSeed().toString("base64url"),
	transports: ["usb"],
	attestation: "none" as const,
};
const secret = "test-only-secret-for-pending-enrollment";
const rpId = "wallet.example.org";

test("requires a valid signature under the server-derived key for none enrollment", async () => {
	const pending = await createEnrollmentProof(
		registration,
		"one-time-challenge",
		Buffer.alloc(32, 7),
		rpId,
		secret,
	);
	const proof = await readEnrollmentProof(
		pending.registrationToken,
		"alice",
		rpId,
		secret,
	);
	assert.deepEqual(proof, pending.proof);
	for (const format of ["der", "compact"] as const) {
		const signature = proofSignature(proof, format);
		assert.doesNotThrow(() => verifyEnrollmentProofSignature(proof, signature));
		signature[signature.length - 1] ^= 1;
		assert.throws(() => verifyEnrollmentProofSignature(proof, signature));
	}
	const signature = proofSignature(proof);
	assert.throws(() =>
		verifyEnrollmentProofSignature(
			{ ...proof, data: Buffer.from("changed message").toString("base64url") },
			signature,
		),
	);
	const other = await createEnrollmentProof(
		registration,
		"different-challenge",
		Buffer.alloc(32, 9),
		rpId,
		secret,
	);
	assert.notEqual(other.proof.key.ticket, proof.key.ticket);
	assert.throws(() => verifyEnrollmentProofSignature(other.proof, signature));
});

test("binds provisional enrollment to its account, RP, contents, purpose and expiry", async () => {
	const pending = await createEnrollmentProof(
		registration,
		"challenge",
		Buffer.alloc(32),
		rpId,
		secret,
	);
	await assert.rejects(() =>
		readEnrollmentProof(pending.registrationToken, "bob", rpId, secret),
	);
	await assert.rejects(() =>
		readEnrollmentProof(
			pending.registrationToken,
			"alice",
			"evil.example.org",
			secret,
		),
	);
	await assert.rejects(() =>
		readEnrollmentProof(
			pending.registrationToken,
			"alice",
			rpId,
			"wrong secret",
		),
	);
	const parts = pending.registrationToken.split(".");
	const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
	payload.proof.registration.credentialId = "attacker";
	parts[1] = Buffer.from(JSON.stringify(payload)).toString("base64url");
	await assert.rejects(() =>
		readEnrollmentProof(parts.join("."), "alice", rpId, secret),
	);
	const expired = await new SignJWT({
		purpose: "wwwallet-preview-sign-enrollment",
		proof: pending.proof,
	})
		.setProtectedHeader({
			alg: "HS256",
			typ: "wwwallet-preview-sign-enrollment+jwt",
		})
		.setSubject("alice")
		.setAudience("wwwallet-preview-sign-enrollment")
		.setExpirationTime(1)
		.sign(Buffer.from(secret));
	await assert.rejects(() =>
		readEnrollmentProof(expired, "alice", rpId, secret),
	);
	const loginToken = await new SignJWT({ v: 1, uuid: "alice" })
		.setProtectedHeader({ alg: "HS256" })
		.sign(Buffer.from(secret));
	await assert.rejects(() =>
		readEnrollmentProof(loginToken, "alice", rpId, secret),
	);
});
