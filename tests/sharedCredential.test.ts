import { strict as assert } from "node:assert";
import { test } from "node:test";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { Encoder } from "cbor-x";
import { verifyRegistrationResponse } from "@simplewebauthn/server";
import { validateCombinedRegistration } from "../src/combinedRegistration";
import { verifySharedCredentialAssertion } from "../src/sharedCredential";
import {
	createEnrollmentProof,
	verifyEnrollmentProofSignature,
} from "../src/previewSignEnrollment";
import { getSignedPreviewSignature } from "../src/previewSign";
import { publicSeed, proofSignature } from "./previewSignEnrollment.test";

const encoder = new Encoder({
	useRecords: false,
	mapsAsObjects: false,
	tagUint8Array: false,
	variableMapSize: true,
});
const encode = (value: unknown) => Buffer.from(encoder.encode(value));
const hash = (value: Buffer | string) =>
	createHash("sha256").update(value).digest();
export const rpId = "wallet.example.org";
export const origin = `https://${rpId}`;

export function sharedPasskey(challenge: Buffer, suffix = "") {
	const { privateKey, publicKey } = generateKeyPairSync("ec", {
		namedCurve: "prime256v1",
	});
	const jwk = publicKey.export({ format: "jwk" });
	const publicKeyCose = encode(
		new Map<number, unknown>([
			[1, 2],
			[3, -7],
			[-1, 1],
			[-2, Buffer.from(jwk.x!, "base64url")],
			[-3, Buffer.from(jwk.y!, "base64url")],
		]),
	);
	const credentialId = Buffer.from(`shared passkey ${suffix}`);
	const clientDataJSON = Buffer.from(
		JSON.stringify({
			type: "webauthn.create",
			challenge: challenge.toString("base64url"),
			origin,
		}),
	);
	const attestationData = (
		key: Buffer,
		id: Buffer,
		extension: Map<number, unknown>,
	) => {
		const length = Buffer.alloc(2);
		length.writeUInt16BE(id.length);
		return Buffer.concat([
			hash(rpId),
			Buffer.from([0xc5]),
			Buffer.alloc(4),
			Buffer.alloc(16),
			length,
			id,
			key,
			encode(new Map([["previewSign", extension]])),
		]);
	};
	const attestationObject = encode({
		fmt: "none",
		authData: attestationData(
			publicKeyCose,
			credentialId,
			new Map([[3, -65539]]),
		),
		attStmt: {},
	});
	const signingAttestation = encode({
		fmt: "none",
		authData: attestationData(
			publicSeed(),
			Buffer.from("seed handle"),
			new Map([[4, 5]]),
		),
		attStmt: {},
	});
	const credential = {
		id: credentialId.toString("base64url"),
		rawId: credentialId,
		type: "public-key",
		response: { clientDataJSON, attestationObject, transports: ["usb"] },
		clientExtensionResults: { prf: { enabled: true } },
	};
	function assertion(
		challenge: Buffer,
		counter: number,
		previewSignature?: Uint8Array,
		options: { origin?: string; rpId?: string; uv?: boolean } = {},
	) {
		const count = Buffer.alloc(4);
		count.writeUInt32BE(counter);
		const authData = Buffer.concat([
			hash(options.rpId ?? rpId),
			Buffer.from([
				(previewSignature ? 0x80 : 0) | (options.uv === false ? 1 : 5),
			]),
			count,
			...(previewSignature
				? [encode(new Map([["previewSign", new Map([[6, previewSignature]])]]))]
				: []),
		]);
		const clientDataJSON = Buffer.from(
			JSON.stringify({
				type: "webauthn.get",
				challenge: challenge.toString("base64url"),
				origin: options.origin ?? origin,
			}),
		);
		return {
			id: credential.id,
			rawId: credentialId,
			type: "public-key",
			response: {
				authenticatorData: authData,
				clientDataJSON,
				signature: sign(
					"sha256",
					Buffer.concat([authData, hash(clientDataJSON)]),
					privateKey,
				),
			},
			clientExtensionResults: {},
		};
	}
	return {
		credential,
		signingAttestation,
		publicKeyCose,
		credentialId,
		assertion,
	};
}

const expected = (challenge: Buffer) => ({
	challenge: challenge.toString("base64url"),
	origin,
	rpId,
});

test("a single registration supplies the login credential, PRF capability and ARKG seed", async () => {
	const challenge = Buffer.alloc(32, 1),
		p = sharedPasskey(challenge);
	assert.deepEqual(
		validateCombinedRegistration(p.credential, p.signingAttestation, rpId),
		p.signingAttestation,
	);
	const verification = await verifyRegistrationResponse({
		response: {
			id: p.credential.id,
			rawId: p.credential.id,
			type: "public-key",
			clientExtensionResults: {},
			response: {
				attestationObject:
					p.credential.response.attestationObject.toString("base64url"),
				clientDataJSON:
					p.credential.response.clientDataJSON.toString("base64url"),
			},
		},
		expectedChallenge: challenge.toString("base64url"),
		expectedOrigin: origin,
		expectedRPID: rpId,
		requireUserVerification: true,
	});
	assert.equal(verification.verified, true);
	assert.equal(verification.registrationInfo!.credential.id, p.credential.id);
});

test("refuses missing PRF, missing seed output and mismatched IDs at combined registration", () => {
	const p = sharedPasskey(Buffer.alloc(32));
	assert.throws(
		() =>
			validateCombinedRegistration(
				{ ...p.credential, clientExtensionResults: {} },
				p.signingAttestation,
				rpId,
			),
		/PRF/,
	);
	assert.throws(() =>
		validateCombinedRegistration(p.credential, undefined, rpId),
	);
	assert.throws(
		() =>
			validateCombinedRegistration(
				{ ...p.credential, id: "other" },
				p.signingAttestation,
				rpId,
			),
		/ID mismatch/,
	);
});

test("enrollment, login, signing and another login share a monotonically increasing counter", async () => {
	const p = sharedPasskey(Buffer.alloc(32));
	const record = {
		credentialId: p.credentialId,
		publicKeyCose: p.publicKeyCose,
		signatureCount: 0,
	};
	const challenge = Buffer.alloc(32, 2);
	const pending = await createEnrollmentProof(
		{
			id: "seed",
			userUuid: "alice",
			webauthnCredentialId: "shared-row",
			credentialId: p.credential.id,
			publicSeed: publicSeed().toString("base64url"),
			keyHandle: "aGFuZGxl",
			transports: ["usb"],
			attestation: "none",
		},
		"challenge-id",
		challenge,
		rpId,
		"test-secret",
	);
	const proof = pending.proof;
	const signed = p.assertion(challenge, 1, proofSignature(proof));
	const enrollment = await verifySharedCredentialAssertion(
		record,
		signed,
		expected(challenge),
	);
	verifyEnrollmentProofSignature(
		proof,
		getSignedPreviewSignature(enrollment.authenticatorData),
	);
	record.signatureCount = enrollment.newCounter;
	for (const counter of [2, 3, 4]) {
		const assertion = p.assertion(
			challenge,
			counter,
			counter === 3 ? proofSignature(proof) : undefined,
		);
		const verified = await verifySharedCredentialAssertion(
			record,
			assertion,
			expected(challenge),
		);
		record.signatureCount = verified.newCounter;
	}
	assert.equal(record.signatureCount, 4);
	await assert.rejects(
		() =>
			verifySharedCredentialAssertion(
				record,
				p.assertion(challenge, 3),
				expected(challenge),
			),
		/counter/,
	);
});

test("shared assertions reject wrong credential, origin, RP, challenge, UV and signed-data tampering", async () => {
	const challenge = Buffer.alloc(32, 3),
		p = sharedPasskey(challenge);
	const record = {
		credentialId: p.credentialId,
		publicKeyCose: p.publicKeyCose,
		signatureCount: 0,
	};
	for (const options of [
		{ origin: "https://evil.example" },
		{ rpId: "evil.example" },
		{ uv: false },
	])
		await assert.rejects(() =>
			verifySharedCredentialAssertion(
				record,
				p.assertion(challenge, 1, undefined, options),
				expected(challenge),
			),
		);
	await assert.rejects(() =>
		verifySharedCredentialAssertion(
			record,
			p.assertion(challenge, 1),
			expected(Buffer.alloc(32, 4)),
		),
	);
	const assertion = p.assertion(challenge, 1, Buffer.alloc(64, 1));
	await assert.rejects(
		() =>
			verifySharedCredentialAssertion(
				record,
				{ ...assertion, id: "different" },
				expected(challenge),
			),
		/different credential/,
	);
	assertion.response.authenticatorData[
		assertion.response.authenticatorData.length - 1
	] ^= 1;
	await assert.rejects(() =>
		verifySharedCredentialAssertion(record, assertion, expected(challenge)),
	);
});

test("counterless authenticators remain supported for both uses", async () => {
	const challenge = Buffer.alloc(32, 4),
		p = sharedPasskey(challenge);
	const record = {
		credentialId: p.credentialId,
		publicKeyCose: p.publicKeyCose,
		signatureCount: 0,
	};
	for (const _ of [1, 2])
		assert.equal(
			(
				await verifySharedCredentialAssertion(
					record,
					p.assertion(challenge, 0),
					expected(challenge),
				)
			).newCounter,
			0,
		);
});
