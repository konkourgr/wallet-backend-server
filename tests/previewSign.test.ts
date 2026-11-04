import { strict as assert } from "node:assert";
import { test } from "node:test";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	createHash,
	generateKeyPairSync,
	sign,
	X509Certificate,
} from "node:crypto";
import { Encoder, Decoder } from "cbor-x";
import { verifyRegistrationResponse } from "@simplewebauthn/server";
import { enrollmentFailure } from "../src/previewSignErrors";
import {
	assertPreviewSignChallenge,
	getSignedPreviewSignature,
	verifySigningSeedAttestation,
} from "../src/previewSign";

const encoder = new Encoder({
	useRecords: false,
	mapsAsObjects: false,
	tagUint8Array: false,
	variableMapSize: true,
});
const encode = (value: unknown) => Buffer.from(encoder.encode(value));
const hash = (value: string | Buffer) =>
	createHash("sha256").update(value).digest();
const rpId = "wallet.example.org";
const challenge = Buffer.alloc(32, 7).toString("base64url");
const clientData = Buffer.from(
	JSON.stringify({
		type: "webauthn.create",
		challenge,
		origin: `https://${rpId}`,
	}),
);

// Ephemeral, self-signed test attestation only. No production signing material.
function createAttestationCertificate() {
	const directory = mkdtempSync(join(tmpdir(), "preview-sign-attestation-"));
	try {
		execFileSync(
			"openssl",
			[
				"req",
				"-x509",
				"-newkey",
				"ec",
				"-pkeyopt",
				"ec_paramgen_curve:P-256",
				"-nodes",
				"-keyout",
				join(directory, "key.pem"),
				"-out",
				join(directory, "cert.pem"),
				"-days",
				"1",
				"-subj",
				"/C=US/O=wwWallet tests/OU=Authenticator Attestation/CN=Test attestation",
				"-addext",
				"basicConstraints=critical,CA:FALSE",
			],
			{ stdio: "ignore" },
		);
		return {
			key: readFileSync(join(directory, "key.pem")),
			certificate: new X509Certificate(
				readFileSync(join(directory, "cert.pem")),
			).raw,
		};
	} finally {
		rmSync(directory, { recursive: true, force: true });
	}
}
const firstAttestation = createAttestationCertificate();
const secondAttestation = createAttestationCertificate();

function ecKey() {
	const { publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
	const jwk = publicKey.export({ format: "jwk" });
	return new Map<number, unknown>([
		[1, 2],
		[3, -7],
		[-1, 1],
		[-2, Buffer.from(jwk.x!, "base64url")],
		[-3, Buffer.from(jwk.y!, "base64url")],
	]);
}
function authData(
	key: Map<number, unknown>,
	id: Buffer,
	extensions: Map<number, unknown>,
	flags = 0xc5,
	rp = rpId,
) {
	const length = Buffer.alloc(2);
	length.writeUInt16BE(id.length);
	return Buffer.concat([
		hash(rp),
		Buffer.from([flags]),
		Buffer.alloc(4),
		Buffer.alloc(16),
		length,
		id,
		encode(key),
		encode(new Map([["previewSign", extensions]])),
	]);
}
function packed(
	data: Buffer,
	client = clientData,
	signer = firstAttestation,
	algorithm = -7,
) {
	return encode({
		fmt: "packed",
		authData: data,
		attStmt: {
			alg: algorithm,
			sig: sign("sha256", Buffer.concat([data, hash(client)]), signer.key),
			x5c: [signer.certificate],
		},
	});
}
function enrollment(
	options: {
		algorithm?: number;
		policy?: number;
		flags?: number;
		rp?: string;
		attestationAlgorithm?: number;
		separateCertificate?: boolean;
	} = {},
) {
	const seed = new Map<number, unknown>([
		[1, -65537],
		[3, -65700],
		[-1, ecKey()],
		[-2, ecKey()],
		[-3, -9],
	]);
	const handle = Buffer.from("test signing handle");
	const outer = packed(
		authData(
			ecKey(),
			Buffer.from("test credential"),
			new Map([[3, options.algorithm ?? -65539]]),
		),
	);
	const inner = packed(
		authData(
			seed,
			handle,
			new Map([[4, options.policy ?? 5]]),
			options.flags,
			options.rp,
		),
		clientData,
		options.separateCertificate ? secondAttestation : firstAttestation,
		options.attestationAlgorithm ?? -7,
	);
	return { outer, inner, seed: encode(seed), handle };
}

test("verifies a normal registration and the separate ARKG signing seed attestation", async () => {
	const { outer, inner, handle, seed } = enrollment();
	const verification = await verifyRegistrationResponse({
		response: {
			id: Buffer.from("test credential").toString("base64url"),
			rawId: Buffer.from("test credential").toString("base64url"),
			type: "public-key",
			response: {
				attestationObject: outer.toString("base64url"),
				clientDataJSON: clientData.toString("base64url"),
			},
			clientExtensionResults: {},
		},
		expectedChallenge: challenge,
		expectedOrigin: `https://${rpId}`,
		expectedRPID: rpId,
		requireUserVerification: true,
	});
	assert.equal(verification.verified, true);
	assert.deepEqual(
		verifySigningSeedAttestation(outer, inner, clientData, rpId),
		{
			keyHandle: handle,
			publicSeed: seed,
			attestation: "packed",
		},
	);
});

test("accepts independently signed seed attestations with a different certificate", () => {
	const { outer, inner, seed, handle } = enrollment({
		separateCertificate: true,
	});
	assert.deepEqual(
		verifySigningSeedAttestation(outer, inner, clientData, rpId),
		{
			publicSeed: seed,
			attestation: "packed",
			keyHandle: handle,
		},
	);
});

test("accepts ESP256 (-9) as an equivalent P-256/SHA-256 attestation signature", () => {
	const { outer, inner } = enrollment({ attestationAlgorithm: -9 });
	assert.doesNotThrow(() =>
		verifySigningSeedAttestation(outer, inner, clientData, rpId),
	);
});

test("rejects substituting a different certificate without a corresponding valid seed signature", () => {
	const { outer, inner } = enrollment();
	const decoded = new Decoder({ mapsAsObjects: false }).decode(inner) as Map<
		string,
		unknown
	>;
	(decoded.get("attStmt") as Map<string, unknown>).set("x5c", [
		secondAttestation.certificate,
	]);
	assert.throws(
		() =>
			verifySigningSeedAttestation(outer, encode(decoded), clientData, rpId),
		/Invalid signing seed attestation signature/,
	);
});

test("reports the specific unsupported attestation field", () => {
	const unsupported = enrollment({ attestationAlgorithm: -35 });
	assert.throws(
		() =>
			verifySigningSeedAttestation(
				unsupported.outer,
				unsupported.inner,
				clientData,
				rpId,
			),
		/algorithm is -35/,
	);
	const { outer, inner } = enrollment();
	const decoded = new Decoder({ mapsAsObjects: false }).decode(inner) as Map<
		string,
		unknown
	>;
	decoded.set("fmt", "none");
	assert.throws(
		() =>
			verifySigningSeedAttestation(outer, encode(decoded), clientData, rpId),
		/must have an empty attestation statement/,
	);
});

test("rejects unsupported algorithms, weak UV policy, missing UV and wrong RP", () => {
	for (const options of [
		{ algorithm: -7 },
		{ policy: 1 },
		{ flags: 0xc1 },
		{ rp: "evil.example.org" },
	]) {
		const { outer, inner } = enrollment(options);
		assert.throws(() =>
			verifySigningSeedAttestation(outer, inner, clientData, rpId),
		);
	}
});

test("rejects substitution of client data or tampering with the signing attestation", () => {
	const { outer, inner } = enrollment();
	assert.throws(() =>
		verifySigningSeedAttestation(
			outer,
			inner,
			Buffer.from("substituted"),
			rpId,
		),
	);
	const corrupted = new Decoder({ mapsAsObjects: false }).decode(inner) as Map<
		string,
		unknown
	>;
	const signature = (corrupted.get("attStmt") as Map<string, unknown>).get(
		"sig",
	) as Uint8Array;
	signature[signature.length - 1] ^= 1;
	assert.throws(
		() =>
			verifySigningSeedAttestation(outer, encode(corrupted), clientData, rpId),
		/Invalid signing seed attestation signature/,
	);
});

test("requires matching ceremony flags and AAGUIDs even when certificates can differ", () => {
	const flags = enrollment({ flags: 0xcd });
	assert.throws(
		() =>
			verifySigningSeedAttestation(flags.outer, flags.inner, clientData, rpId),
		/authenticator flags differ/,
	);
	const { outer, inner } = enrollment();
	const changed = new Decoder({ mapsAsObjects: false }).decode(inner) as Map<
		string,
		unknown
	>;
	(changed.get("authData") as Uint8Array)[37] ^= 1;
	assert.throws(
		() =>
			verifySigningSeedAttestation(outer, encode(changed), clientData, rpId),
		/AAGUIDs differ/,
	);
});

test("isolates challenges by user, ceremony type and signing seed", () => {
	const challengeRecord = {
		userId: { id: "alice" },
		type: "preview-sign:seed-a",
	};
	assert.doesNotThrow(() =>
		assertPreviewSignChallenge(challengeRecord, "alice", "preview-sign:seed-a"),
	);
	for (const [user, purpose] of [
		["bob", "preview-sign:seed-a"],
		["alice", "get"],
		["alice", "preview-sign:seed-b"],
	]) {
		assert.throws(() =>
			assertPreviewSignChallenge(challengeRecord, user, purpose),
		);
	}
});

test("extracts the preview signature from signed authenticator data only", () => {
	const signature = Buffer.alloc(64, 1);
	const data = Buffer.concat([
		hash(rpId),
		Buffer.from([0x85]),
		Buffer.alloc(4),
		encode(new Map([["previewSign", new Map([[6, signature]])]])),
	]);
	assert.deepEqual(getSignedPreviewSignature(data), signature);
	assert.throws(() =>
		getSignedPreviewSignature(
			Buffer.concat([hash(rpId), Buffer.from([5]), Buffer.alloc(4)]),
		),
	);
});

test("distinguishes WebAuthn and signing seed failures without masking their stage", () => {
	const error = new Error("Unsupported certificate algorithm");
	const webauthn = enrollmentFailure("webauthn", error, false);
	const seed = enrollmentFailure("seed_attestation", error, false);
	assert.equal(webauthn.status, 400);
	assert.equal(webauthn.body.code, "PREVIEW_SIGN_WEBAUTHN_FAILED");
	assert.equal(webauthn.body.reason, error.message);
	assert.equal(seed.body.code, "PREVIEW_SIGN_SEED_ATTESTATION_FAILED");
	assert.equal(
		enrollmentFailure("webauthn", error, true).body.reason,
		undefined,
	);
});

test("reports a missing migration as a storage error without exposing SQL or parameters", () => {
	const error = Object.assign(
		new Error("SQL with private request parameters"),
		{
			driverError: { code: "ER_NO_SUCH_TABLE" },
			query: "private SQL",
			parameters: ["private"],
		},
	);
	const failure = enrollmentFailure("storage", error, false);
	assert.equal(failure.status, 500);
	assert.equal(failure.body.code, "PREVIEW_SIGN_MIGRATION_REQUIRED");
	assert.equal(failure.log.databaseCode, "ER_NO_SUCH_TABLE");
	assert.equal(JSON.stringify(failure).includes("private"), false);
});

test("parses a none signing seed as untrusted claims awaiting a signing proof", () => {
	const { outer, inner, seed, handle } = enrollment();
	const decoded = new Decoder({ mapsAsObjects: false }).decode(inner) as Map<
		string,
		unknown
	>;
	decoded.set("fmt", "none");
	decoded.set("attStmt", new Map());
	// Privacy-preserving clients may anonymize the AAGUID.
	(decoded.get("authData") as Uint8Array)[37] ^= 1;
	assert.deepEqual(
		verifySigningSeedAttestation(outer, encode(decoded), clientData, rpId),
		{
			keyHandle: handle,
			publicSeed: seed,
			attestation: "none",
		},
	);
	decoded.set("fmt", "unsupported");
	assert.throws(
		() =>
			verifySigningSeedAttestation(outer, encode(decoded), clientData, rpId),
		/Unsupported/,
	);
});

import "./previewSignEnrollment.test";

import './sharedCredential.test';
