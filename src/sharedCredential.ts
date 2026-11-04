import { verifyAuthenticationResponse } from "@simplewebauthn/server";

export const binary = (value: unknown): Buffer => {
	if (!(value instanceof Uint8Array) || value.length === 0)
		throw new Error("Expected binary WebAuthn data");
	return Buffer.from(value);
};
export type SharedCredential = {
	credentialId: Buffer;
	publicKeyCose: Buffer;
	signatureCount: number;
};

/** Invoke with the authoritative webauthn_credential row locked, then save
 * the counter in the same transaction. Login and previewSign both use it. */
export async function verifySharedCredentialAssertion(
	record: SharedCredential,
	credential: any,
	expected: { challenge: string; origin: string | string[]; rpId: string },
) {
	const id = record.credentialId.toString("base64url");
	if (
		credential?.id !== id ||
		binary(credential.rawId).toString("base64url") !== id
	)
		throw new Error("WebAuthn assertion used a different credential");
	const authenticatorData = binary(credential.response.authenticatorData);
	const result = await verifyAuthenticationResponse({
		response: {
			id,
			rawId: id,
			type: "public-key",
			response: {
				authenticatorData: authenticatorData.toString("base64url"),
				clientDataJSON: binary(credential.response.clientDataJSON).toString(
					"base64url",
				),
				signature: binary(credential.response.signature).toString("base64url"),
			},
			clientExtensionResults: {},
		},
		expectedChallenge: expected.challenge,
		expectedOrigin: expected.origin,
		expectedRPID: expected.rpId,
		requireUserVerification: true,
		credential: {
			id,
			publicKey: new Uint8Array(record.publicKeyCose),
			counter: Number(record.signatureCount),
		},
	});
	if (!result.verified)
		throw new Error("WebAuthn assertion failed verification");
	return {
		authenticatorData,
		newCounter: result.authenticationInfo.newCounter,
	};
}
