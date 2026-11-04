/** Opt-in real MariaDB + HTTP tests. Only accepts an empty, disposable test DB. */
import { test } from "node:test";
import { strict as assert } from "node:assert";
import express from "express";
import bodyParser from "body-parser";
import { sharedPasskey, origin, rpId } from "./sharedCredential.test";
import { proofSignature, publicSeed } from "./previewSignEnrollment.test";
import {
	createEnrollmentProof,
	verifyEnrollmentProofSignature,
} from "../src/previewSignEnrollment";
import { AddSigningCredential1793577600000 } from "../src/migrations/1793577600000-AddSigningCredential";

async function main() {
	if (!process.env.DB_NAME?.startsWith("preview_sign_single_key_test"))
		throw new Error(
			"Use an empty disposable DB named preview_sign_single_key_test*",
		);
	process.env.PREVIEW_SIGN_ENABLED = "true";
	process.env.WEBAUTHN_RP_ID = rpId;
	process.env.WEBAUTHN_ORIGIN = origin;
	const { default: db } = await import("../src/AppDataSource");
	const { config } = await import("../config");
	assert.equal(config.db.dbname, process.env.DB_NAME);
	const {
		jsonStringifyTaggedBinary,
		jsonParseTaggedBinary,
		reviverTaggedBase64UrlToBuffer,
		replacerBufferToTaggedBase64Url,
	} = await import("../src/util/util");
	let server: ReturnType<ReturnType<typeof express>["listen"]> | undefined;
	try {
		const { default: userRouter } = await import("../src/routers/user.router");
		for (let i = 0; i < 200 && !db.isInitialized; i++)
			await new Promise((resolve) => setTimeout(resolve, 50));
		assert.equal(db.isInitialized, true, "test DB connection");
		const tables = await db.query(
			"SELECT COUNT(*) AS n FROM information_schema.tables WHERE table_schema = DATABASE()",
		);
		assert.equal(
			Number(tables[0].n),
			0,
			"Refusing to change a nonempty database",
		);
		await db.runMigrations();
		const app = express();
		app.use(
			bodyParser.json({
				reviver: reviverTaggedBase64UrlToBuffer,
				limit: "2mb",
			}),
		);
		app.set("json replacer", replacerBufferToTaggedBase64Url);
		app.use("/user", userRouter);
		server = app.listen(0, "127.0.0.1");
		await new Promise<void>((resolve) => server!.once("listening", resolve));
		const port = (server.address() as { port: number }).port;
		const post = async (
			path: string,
			body: object,
			token?: string,
			etag?: string,
		) => {
			const response = await fetch(`http://127.0.0.1:${port}${path}`, {
				method: "POST",
				headers: {
					"Content-Type": "application/json",
					...(token ? { Authorization: `Bearer ${token}` } : {}),
					...(etag ? { "X-Private-Data-If-Match": etag } : {}),
				},
				body: jsonStringifyTaggedBinary(body),
			});
			const text = await response.text();
			return {
				status: response.status,
				etag: response.headers.get("x-private-data-etag"),
				data:
					text && response.headers.get("content-type")?.includes("json")
						? jsonParseTaggedBinary(text)
						: text,
			};
		};
		const scalar = async (sql: string, params: unknown[] = []) =>
			Number((await db.query(sql, params))[0].n);
		const register = async (name: string) => {
			const begin = await post("/user/register-webauthn-begin", {
				displayName: name,
			});
			assert.equal(begin.status, 200);
			assert.deepEqual(
				begin.data.createOptions.publicKey.extensions.previewSign.generateKey
					.algorithms,
				[-65539],
			);
			assert.ok(begin.data.createOptions.publicKey.extensions.prf);
			const passkey = sharedPasskey(
				begin.data.createOptions.publicKey.challenge,
				name,
			);
			const finish = await post("/user/register-webauthn-finish", {
				challengeId: begin.data.challengeId,
				displayName: name,
				credential: passkey.credential,
				signingAttestation: passkey.signingAttestation,
				privateData: Buffer.from("test encrypted container"),
			});
			assert.equal(finish.status, 200, JSON.stringify(finish.data));
			return {
				...passkey,
				token: finish.data.appToken as string,
				userId: finish.data.uuid as string,
				etag: finish.etag,
			};
		};
		const alice = await register("alice");
		assert.equal(
			await scalar("SELECT COUNT(*) AS n FROM webauthn_credential"),
			1,
		);
		assert.equal(
			await scalar("SELECT COUNT(*) AS n FROM signing_credential"),
			0,
		);
		const pending = await post(
			"/user/session/preview-sign/register-begin",
			{ credentialId: alice.credential.id },
			alice.token,
		);
		assert.equal(pending.status, 200, JSON.stringify(pending.data));
		assert.equal(pending.data.seed.credentialId, alice.credential.id);
		const proof = {
			key: pending.data.proof.key,
			data: pending.data.proof.data.toString("base64url"),
		} as any;
		const completionBody = {
			registrationToken: pending.data.registrationToken,
			credential: alice.assertion(
				pending.data.proof.challenge,
				1,
				proofSignature(proof),
			),
		};
		const complete = await post(
			"/user/session/preview-sign/register-complete",
			completionBody,
			alice.token,
		);
		assert.equal(complete.status, 200, JSON.stringify(complete.data));
		assert.equal(complete.data.credentialId, alice.credential.id);
		assert.equal(
			await scalar("SELECT COUNT(*) AS n FROM webauthn_credential"),
			1,
			"enrollment must not create another passkey",
		);
		assert.equal(
			await scalar("SELECT COUNT(*) AS n FROM signing_credential"),
			1,
		);
		assert.equal(
			(
				await post(
					"/user/session/preview-sign/register-complete",
					completionBody,
					alice.token,
				)
			).status,
			400,
			"one-time proof",
		);
		const restored = await post(
			"/user/session/preview-sign/register-begin",
			{ credentialId: alice.credential.id },
			alice.token,
		);
		assert.equal(restored.data.alreadyEnrolled, true);
		assert.equal(restored.data.seed.id, complete.data.id);
		const columns = (
			await db.query("SHOW COLUMNS FROM signing_credential")
		).map((column: any) => column.Field);
		assert.equal(
			columns.includes("signatureCount"),
			false,
			"no duplicate counter",
		);
		assert.equal(
			columns.includes("publicKeyCose"),
			false,
			"no duplicate WebAuthn key",
		);
		const counter = () =>
			scalar(
				"SELECT signatureCount AS n FROM webauthn_credential WHERE credentialId=?",
				[alice.credentialId],
			);
		assert.equal(await counter(), 1);
		const login = async (count: number) => {
			const begin = await post("/user/login-webauthn-begin", {});
			assert.equal(begin.status, 200);
			const credential = alice.assertion(
				begin.data.getOptions.publicKey.challenge,
				count,
			);
			return post("/user/login-webauthn-finish", {
				challengeId: begin.data.challengeId,
				credential: {
					...credential,
					response: {
						...credential.response,
						userHandle: Buffer.from(alice.userId),
					},
				},
			});
		};
		assert.equal((await login(2)).status, 200);
		const signingProof = await createEnrollmentProof(
			{
				id: complete.data.id,
				userUuid: alice.userId,
				webauthnCredentialId: "test",
				credentialId: alice.credential.id,
				publicSeed: publicSeed().toString("base64url"),
				keyHandle: "aGFuZGxl",
				transports: ["usb"],
				attestation: "none",
			},
			"signing",
			Buffer.alloc(32, 8),
			rpId,
			"test-only",
		);
		const signRequest = async (count: number, withExtension = true) => {
			const begin = await post(
				"/user/session/preview-sign/sign-begin",
				{ seedId: complete.data.id },
				alice.token,
			);
			assert.equal(begin.status, 200);
			return post(
				"/user/session/preview-sign/sign-finish",
				{
					seedId: complete.data.id,
					challengeId: begin.data.challengeId,
					credential: alice.assertion(
						begin.data.challenge,
						count,
						withExtension ? proofSignature(signingProof.proof) : undefined,
					),
				},
				alice.token,
			);
		};
		const signed = await signRequest(3);
		assert.equal(signed.status, 200);
		verifyEnrollmentProofSignature(
			signingProof.proof,
			Buffer.from(signed.data.signature, "base64url"),
		);
		assert.equal(await counter(), 3);
		assert.equal(
			(await signRequest(4, false)).status,
			400,
			"missing previewSign must fail",
		);
		assert.equal(
			await counter(),
			3,
			"a failed extension check must roll back the counter",
		);
		assert.equal((await login(5)).status, 200);
		const [concurrentLogin, concurrentSign] = await Promise.all([
			login(6),
			signRequest(7),
		]);
		assert.ok([200, 400].includes(concurrentLogin.status));
		assert.equal(concurrentSign.status, 200);
		assert.equal(
			await counter(),
			7,
			"concurrent login/signing must not roll the counter back",
		);
		assert.equal(
			(await login(6)).status,
			400,
			"older counter must be rejected",
		);
		const wrongPurpose = await post(
			"/user/session/preview-sign/sign-begin",
			{ seedId: complete.data.id },
			alice.token,
		);
		const wrongLogin = alice.assertion(wrongPurpose.data.challenge, 8);
		assert.equal(
			(
				await post("/user/login-webauthn-finish", {
					challengeId: wrongPurpose.data.challengeId,
					credential: {
						...wrongLogin,
						response: {
							...wrongLogin.response,
							userHandle: Buffer.from(alice.userId),
						},
					},
				})
			).status,
			400,
		);
		assert.equal(await counter(), 7);
		const bob = await register("bob");
		assert.equal(
			(
				await post(
					"/user/session/preview-sign/register-begin",
					{ credentialId: alice.credential.id },
					bob.token,
				)
			).status,
			400,
		);
		assert.equal(
			(
				await post(
					"/user/session/preview-sign/register-complete",
					completionBody,
					bob.token,
				)
			).status,
			400,
		);
		assert.equal(
			(
				await post(
					"/user/session/preview-sign/sign-begin",
					{ seedId: complete.data.id },
					bob.token,
				)
			).status,
			404,
		);
		const crossOwner = await post(
			"/user/session/webauthn/register-begin",
			{},
			alice.token,
		);
		const crossPasskey = sharedPasskey(
			crossOwner.data.createOptions.publicKey.challenge,
			"cross-owner",
		);
		assert.equal(
			(
				await post(
					"/user/session/webauthn/register-finish",
					{
						challengeId: crossOwner.data.challengeId,
						credential: crossPasskey.credential,
						signingAttestation: crossPasskey.signingAttestation,
						privateData: Buffer.from("forbidden"),
					},
					bob.token,
					bob.etag!,
				)
			).status,
			400,
		);
		const missingSeedBegin = await post("/user/register-webauthn-begin", {
			displayName: "missing seed",
		});
		const missingSeed = sharedPasskey(
			missingSeedBegin.data.createOptions.publicKey.challenge,
			"missing seed",
		);
		assert.equal(
			(
				await post("/user/register-webauthn-finish", {
					challengeId: missingSeedBegin.data.challengeId,
					credential: missingSeed.credential,
					privateData: Buffer.from("incomplete"),
				})
			).status,
			400,
		);
		const invalidBegin = await post("/user/register-webauthn-begin", {
			displayName: "invalid origin",
		});
		const invalid = sharedPasskey(
			invalidBegin.data.createOptions.publicKey.challenge,
			"invalid origin",
		);
		const invalidClientData = JSON.parse(
			invalid.credential.response.clientDataJSON.toString(),
		);
		invalidClientData.origin = "https://evil.example";
		invalid.credential.response.clientDataJSON = Buffer.from(
			JSON.stringify(invalidClientData),
		);
		assert.equal(
			(
				await post("/user/register-webauthn-finish", {
					challengeId: invalidBegin.data.challengeId,
					credential: invalid.credential,
					signingAttestation: invalid.signingAttestation,
					privateData: Buffer.from("invalid registration"),
				})
			).status,
			400,
		);
		assert.equal(await scalar("SELECT COUNT(*) AS n FROM user"), 2);
		// Adding another unlocking passkey also requests both extensions.
		const add = await post(
			"/user/session/webauthn/register-begin",
			{},
			alice.token,
		);
		assert.equal(add.status, 200);
		assert.ok(add.data.createOptions.publicKey.extensions.previewSign);
		const second = sharedPasskey(
			add.data.createOptions.publicKey.challenge,
			"alice second",
		);
		const added = await post(
			"/user/session/webauthn/register-finish",
			{
				challengeId: add.data.challengeId,
				name: "Second shared key",
				credential: second.credential,
				signingAttestation: second.signingAttestation,
				privateData: Buffer.from("updated test encrypted container"),
			},
			alice.token,
			alice.etag!,
		);
		assert.equal(added.status, 200, JSON.stringify(added.data));
		assert.equal(
			await scalar(
				"SELECT COUNT(*) AS n FROM webauthn_credential WHERE pendingSigningAttestation IS NOT NULL",
			),
			2,
		);
		const row = (
			await db.query(
				"SELECT id FROM webauthn_credential WHERE credentialId=?",
				[alice.credentialId],
			)
		)[0];
		const removed = await post(
			`/user/session/webauthn/credential/${row.id}/delete`,
			{ privateData: Buffer.from("after deletion") },
			alice.token,
			added.etag!,
		);
		assert.equal(removed.status, 204, JSON.stringify(removed.data));
		assert.equal(
			await scalar("SELECT COUNT(*) AS n FROM signing_credential"),
			0,
			"shared credential deletion must cascade to the seed",
		);
		config.previewSignEnabled = false;
		const ordinaryBegin = await post("/user/register-webauthn-begin", {
			displayName: "ordinary PRF wallet",
		});
		assert.equal(
			ordinaryBegin.data.createOptions.publicKey.extensions.previewSign,
			undefined,
		);
		const ordinary = sharedPasskey(
			ordinaryBegin.data.createOptions.publicKey.challenge,
			"ordinary",
		);
		const ordinaryFinish = await post("/user/register-webauthn-finish", {
			challengeId: ordinaryBegin.data.challengeId,
			credential: ordinary.credential,
			displayName: "ordinary PRF wallet",
			privateData: Buffer.from("ordinary encrypted container"),
		});
		assert.equal(ordinaryFinish.status, 200);
		const disabledSigning = await post(
			"/user/session/preview-sign/register-begin",
			{ credentialId: ordinary.credential.id },
			ordinaryFinish.data.appToken,
		);
		assert.equal(disabledSigning.status, 404);
		assert.equal(disabledSigning.data.code, "PREVIEW_SIGN_DISABLED");
		config.previewSignEnabled = true;
		const runner = db.createQueryRunner();
		await runner.connect();
		try {
			const migration = new AddSigningCredential1793577600000();
			await migration.down(runner);
			await migration.up(runner);
		} finally {
			await runner.release();
		}
		console.log(
			"PASS: fresh migration, combined signup/add-passkey, one credential, proof/replay/ownership, shared counter + concurrency, signing, recovery, deletion cascade, migration down/up",
		);
	} finally {
		if (server) {
			server.closeAllConnections();
			await new Promise<void>((resolve) => server!.close(() => resolve()));
		}
		if (db.isInitialized) await db.destroy();
	}
}
test("single-key HTTP/MariaDB enrollment, counters and lifecycle", main);
