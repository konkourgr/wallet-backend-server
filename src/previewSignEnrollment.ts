import { randomBytes, createPublicKey, verify } from 'node:crypto';
import { SignJWT, jwtVerify, type JWK } from 'jose';
import { deriveArkgPublicKey } from './arkg';

const audience = 'wwwallet-preview-sign-enrollment';
export type EnrollmentRegistration = {
	id: string;
	userUuid: string;
	credentialId: string;
	webauthnCredentialId: string;
	keyHandle: string;
	publicSeed: string;
	transports: string[];
	attestation: 'packed' | 'none';
};
export type EnrollmentProof = {
	registration: EnrollmentRegistration;
	challengeId: string;
	challenge: string;
	rpId: string;
	data: string;
	key: {
		type: 'arkg';
		kid: string;
		alg: 'ES256';
		publicKey: JWK;
		seedId: string;
		ticket: string;
		context: string;
	};
};

/** No signing registration is persisted until this one-time proof succeeds. */
export async function createEnrollmentProof(
	registration: EnrollmentRegistration,
	challengeId: string,
	challenge: Buffer,
	rpId: string,
	secret: string,
) {
	const context = Buffer.from('wwWallet:previewSign:enrollment:v1');
	const derived = deriveArkgPublicKey(Buffer.from(registration.publicSeed, 'base64url'), randomBytes(32), context);
	const proof: EnrollmentProof = {
		registration,
		challengeId,
		challenge: challenge.toString('base64url'),
		rpId,
		data: Buffer.concat([Buffer.from('wwWallet:previewSign:enrollment:v1\0'), challenge]).toString('base64url'),
		key: {
			type: 'arkg',
			kid: registration.id,
			alg: 'ES256',
			publicKey: derived.publicKeyJwk,
			seedId: registration.id,
			ticket: Buffer.from(derived.ticket).toString('base64url'),
			context: context.toString('base64url'),
		},
	};
	const registrationToken = await new SignJWT({ purpose: audience, proof })
		.setProtectedHeader({ alg: 'HS256', typ: `${audience}+jwt` })
		.setSubject(registration.userUuid)
		.setAudience(audience)
		.setIssuedAt()
		.setExpirationTime('5m')
		.sign(Buffer.from(secret));
	return { registrationToken, proof };
}

export async function readEnrollmentProof(token: string, userUuid: string, rpId: string, secret: string): Promise<EnrollmentProof> {
	const result = await jwtVerify(token, Buffer.from(secret), {
		algorithms: ['HS256'],
		audience,
		subject: userUuid,
		typ: `${audience}+jwt`,
	});
	const proof = result.payload.proof as EnrollmentProof | undefined;
	if (result.payload.purpose !== audience || !proof || proof.registration.userUuid !== userUuid || proof.rpId !== rpId)
		throw new Error('Invalid enrollment proof token');
	return proof;
}

/** Verify the extension signature only after verifying its enclosing WebAuthn assertion. */
export function verifyEnrollmentProofSignature(proof: EnrollmentProof, signature: Uint8Array): void {
	const key = createPublicKey({ key: proof.key.publicKey, format: 'jwk' });
	for (const dsaEncoding of signature.length === 64 ? (['der', 'ieee-p1363'] as const) : (['der'] as const)) {
		try {
			if (verify('sha256', Buffer.from(proof.data, 'base64url'), { key, dsaEncoding }, signature)) return;
		} catch {
			/* Reject malformed encodings after trying the supported alternatives. */
		}
	}
	throw new Error('Enrollment signature does not match the server-derived ARKG public key');
}
