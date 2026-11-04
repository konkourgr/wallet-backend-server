import { createHash, ECDH, timingSafeEqual, verify, X509Certificate } from 'node:crypto';
import { Decoder } from 'cbor-x';
import { decodeAttestationObject, getCertificateInfo, parseAuthenticatorData } from '@simplewebauthn/server/helpers';

export const PREVIEW_SIGN_ALGORITHM = -65539;
const decoder = new Decoder({ mapsAsObjects: false });
const hash = (data: Uint8Array | string) => createHash('sha256').update(data).digest();

export function assertPreviewSignChallenge(
	challenge: { type: string; userId?: { id: string } | null },
	userId: string,
	purpose: string,
): void {
	if (challenge.userId?.id !== userId || challenge.type !== purpose) {
		throw new Error('WebAuthn challenge belongs to another user or ceremony');
	}
}

function extension(authData: ReturnType<typeof parseAuthenticatorData>): Map<number, unknown> {
	if (!authData.extensionsDataBuffer) throw new Error('Missing signed previewSign extension');
	const extensions: unknown = decoder.decode(authData.extensionsDataBuffer);
	const result: unknown = extensions instanceof Map ? extensions.get('previewSign') : undefined;
	if (!(result instanceof Map)) throw new Error('Missing signed previewSign extension');
	return result;
}

/** Verify the seed's separate packed attestation, which normal WebAuthn
 * registration verification does not cover. Certificate chain trust is not
 * asserted. A none result contains untrusted seed claims. In both cases the
 * caller must verify an enrollment signing proof before storing the seed.
 */
export function verifySigningSeedAttestation(
	outerAttestation: Uint8Array,
	signingAttestation: Uint8Array,
	clientDataJSON: Uint8Array,
	rpId: string,
) {
	const outer = decodeAttestationObject(Uint8Array.from(outerAttestation));
	const inner = decodeAttestationObject(Uint8Array.from(signingAttestation));
	const outerData = parseAuthenticatorData(outer.get('authData'));
	const innerBytes = inner.get('authData');
	const innerData = parseAuthenticatorData(innerBytes);
	if (extension(outerData).get(3) !== PREVIEW_SIGN_ALGORITHM || extension(innerData).get(4) !== 5) {
		throw new Error('Expected previewSign ARKG-P256 with user verification required');
	}
	if (
		!innerData.flags.up ||
		!innerData.flags.uv ||
		!innerData.credentialID ||
		!innerData.credentialPublicKey ||
		!timingSafeEqual(Buffer.from(innerData.rpIdHash), hash(rpId))
	) {
		throw new Error('Invalid signing seed authenticator data');
	}
	const format = inner.get('fmt');
	if (format !== 'packed' && format !== 'none') throw new Error(`Unsupported signing seed attestation format: ${format}`);
	if (outerData.flagsBuf[0] !== innerData.flagsBuf[0]) throw new Error('Signing seed and credential authenticator flags differ');
	// A client may anonymize AAGUIDs when it conveys no attestation. They are
	// structural metadata only in that case; the subsequent signing proof is required.
	if (format === 'packed') {
		if (!innerData.aaguid || !outerData.aaguid || !Buffer.from(innerData.aaguid).equals(Buffer.from(outerData.aaguid)))
			throw new Error('Signing seed and credential attestation AAGUIDs differ');
		const innerCert = inner.get('attStmt').get('x5c')?.[0];
		const signature = inner.get('attStmt').get('sig');
		if (!innerCert) throw new Error('Signing seed packed attestation has no x5c certificate');
		if (!signature) throw new Error('Signing seed attestation has no signature');
		const attestationAlgorithm = inner.get('attStmt').get('alg');
		// ES256 (-7) and ESP256 (-9) both mean ECDSA/P-256/SHA-256 in
		// WebAuthn. This identifier describes the attestation signature, not
		// the separate -65539 ARKG signing operation negotiated above.
		if (attestationAlgorithm !== -7 && attestationAlgorithm !== -9)
			throw new Error(`Signing seed attestation algorithm is ${attestationAlgorithm}; expected ES256 (-7) or ESP256 (-9)`);
		const certificateInfo = getCertificateInfo(Uint8Array.from(innerCert));
		if (
			certificateInfo.version !== 2 ||
			certificateInfo.basicConstraintsCA ||
			certificateInfo.subject.OU !== 'Authenticator Attestation' ||
			!certificateInfo.subject.CN ||
			!certificateInfo.subject.O ||
			certificateInfo.subject.C?.length !== 2
		)
			throw new Error('Signing seed certificate does not satisfy packed attestation certificate requirements');
		const now = new Date();
		if (certificateInfo.notBefore > now || certificateInfo.notAfter < now)
			throw new Error('Signing seed attestation certificate is expired or not yet valid');
		const cert = new X509Certificate(innerCert);
		if (
			cert.publicKey.asymmetricKeyType !== 'ec' ||
			cert.publicKey.asymmetricKeyDetails?.namedCurve !== 'prime256v1' ||
			!verify('sha256', Buffer.concat([Buffer.from(innerBytes), hash(clientDataJSON)]), cert.publicKey, signature)
		) {
			throw new Error('Invalid signing seed attestation signature');
		}
	} else if (inner.get('attStmt').size !== 0) {
		throw new Error('None signing seed attestation must have an empty attestation statement');
	}
	const seed: unknown = decoder.decode(innerData.credentialPublicKey);
	if (
		!(seed instanceof Map) ||
		seed.get(1) !== -65537 ||
		seed.get(3) !== -65700 ||
		(seed.has(-3) && seed.get(-3) !== -9 && seed.get(-3) !== -7)
	) {
		throw new Error('Unsupported ARKG public seed');
	}
	for (const label of [-1, -2]) {
		const point: unknown = seed.get(label);
		if (!(point instanceof Map) || point.get(1) !== 2 || point.get(-1) !== 1 || point.has(-4))
			throw new Error('Invalid public ARKG seed point');
		const x = point.get(-2),
			y = point.get(-3);
		if (!(x instanceof Uint8Array) || x.length !== 32) throw new Error('Invalid ARKG x coordinate');
		const encoded =
			typeof y === 'boolean'
				? Buffer.concat([Buffer.from([y ? 3 : 2]), Buffer.from(x)])
				: y instanceof Uint8Array && y.length === 32
					? Buffer.concat([Buffer.from([4]), Buffer.from(x), Buffer.from(y)])
					: undefined;
		if (!encoded) throw new Error('Invalid ARKG y coordinate');
		ECDH.convertKey(encoded, 'prime256v1'); // Reject off-curve points.
	}
	return {
		keyHandle: Buffer.from(innerData.credentialID),
		publicSeed: Buffer.from(innerData.credentialPublicKey),
		attestation: format as 'packed' | 'none',
	};
}

/** Call only after verifying the WebAuthn assertion signature. */
export function getSignedPreviewSignature(authenticatorData: Uint8Array): Buffer {
	const signature = extension(parseAuthenticatorData(Uint8Array.from(authenticatorData))).get(6);
	if (!(signature instanceof Uint8Array) || signature.length === 0 || signature.length > 80) {
		throw new Error('Missing or invalid signed previewSign signature');
	}
	return Buffer.from(signature);
}
