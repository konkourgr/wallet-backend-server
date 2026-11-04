import { Router } from 'express';
import { randomUUID } from 'node:crypto';
import { config } from '../../config';
import AppDataSource from '../AppDataSource';
import { createChallenge, popChallenge } from '../entities/WebauthnChallenge.entity';
import { SigningCredentialEntity } from '../entities/SigningCredential.entity';
import { WebauthnCredentialEntity } from '../entities/user.entity';
import { enrollmentFailure, type EnrollmentStage } from '../previewSignErrors';
import { createEnrollmentProof, readEnrollmentProof, verifyEnrollmentProofSignature } from '../previewSignEnrollment';
import {
	assertPreviewSignChallenge,
	getSignedPreviewSignature,
	PREVIEW_SIGN_ALGORITHM,
	verifySigningSeedAttestation,
} from '../previewSign';
import { verifySharedCredentialAssertion } from '../sharedCredential';
import { lockSharedCredential } from '../sharedCredentialStorage';

export const previewSignRouter = Router();
previewSignRouter.use((_req, res, next) => {
	if (!config.previewSignEnabled)
		return res.status(404).send({
			error: 'Hardware signing is disabled on the backend. Enable PREVIEW_SIGN_ENABLED and restart the server.',
			code: 'PREVIEW_SIGN_DISABLED',
		});
	next();
});
const repository = () => AppDataSource.getRepository(SigningCredentialEntity);
const publicSeed = (seed: SigningCredentialEntity, passkey: WebauthnCredentialEntity) => ({
	id: seed.id,
	credentialId: passkey.credentialId.toString('base64url'),
	keyHandle: seed.keyHandle.toString('base64url'),
	publicSeed: seed.publicSeed.toString('base64url'),
	algorithm: PREVIEW_SIGN_ALGORITHM,
	transports: passkey.transports,
	attestation: seed.attestation,
});

/** Finishes an EXISTING combined PRF + previewSign registration. No create(). */
previewSignRouter.post('/register-begin', async (req, res) => {
	let stage: EnrollmentStage = 'request';
	try {
		if (typeof req.body.credentialId !== 'string') throw new Error('Choose an unlocking passkey');
		const passkey = await AppDataSource.getRepository(WebauthnCredentialEntity).findOne({
			where: {
				credentialId: Buffer.from(req.body.credentialId, 'base64url'),
				user: { uuid: req.user!.id },
			},
		});
		if (!passkey || passkey.credentialId.toString('base64url') !== req.body.credentialId || !passkey.prfCapable)
			throw new Error('PRF passkey does not belong to this account');
		const existing = await repository().findOneBy({
			webauthnCredentialId: passkey.id,
			userUuid: req.user!.id.id,
		});
		if (existing)
			return res.send({
				alreadyEnrolled: true,
				seed: publicSeed(existing, passkey),
			});
		if (!passkey.pendingSigningAttestation)
			throw new Error('This passkey was not created with previewSign. Add a compatible passkey with hardware signing enabled.');
		stage = 'seed_attestation';
		const seed = verifySigningSeedAttestation(
			passkey.attestationObject,
			passkey.pendingSigningAttestation,
			passkey.create_clientDataJSON,
			config.webauthn.rp.id,
		);
		stage = 'proof';
		const id = randomUUID();
		const challenge = await createChallenge(`preview-sign:enroll:${id}`, req.user!.id);
		if (challenge.err) throw new Error('Failed to create enrollment proof challenge');
		const pending = await createEnrollmentProof(
			{
				id,
				userUuid: req.user!.id.id,
				webauthnCredentialId: passkey.id,
				credentialId: passkey.credentialId.toString('base64url'),
				keyHandle: seed.keyHandle.toString('base64url'),
				publicSeed: seed.publicSeed.toString('base64url'),
				transports: passkey.transports,
				attestation: seed.attestation,
			},
			challenge.unwrap().id,
			challenge.unwrap().challenge,
			config.webauthn.rp.id,
			config.appSecret,
		);
		res.send({
			registrationToken: pending.registrationToken,
			seed: {
				id,
				credentialId: passkey.credentialId.toString('base64url'),
				keyHandle: seed.keyHandle.toString('base64url'),
				publicSeed: seed.publicSeed.toString('base64url'),
				transports: passkey.transports,
				algorithm: PREVIEW_SIGN_ALGORITHM,
				attestation: seed.attestation,
			},
			proof: {
				challenge: challenge.unwrap().challenge,
				key: pending.proof.key,
				data: Buffer.from(pending.proof.data, 'base64url'),
			},
		});
	} catch (error) {
		const failure = enrollmentFailure(stage, error);
		console.error('[previewSign] Shared-passkey enrollment failed', failure.log);
		res.status(failure.status).send(failure.body);
	}
});

previewSignRouter.post('/register-complete', async (req, res) => {
	let stage: EnrollmentStage = 'proof';
	try {
		if (typeof req.body.registrationToken !== 'string') throw new Error('Missing enrollment proof token');
		const proof = await readEnrollmentProof(req.body.registrationToken, req.user!.id.id, config.webauthn.rp.id, config.appSecret);
		const challenge = await popChallenge(proof.challengeId);
		if (challenge.err) throw new Error('Enrollment proof challenge is expired or already used');
		assertPreviewSignChallenge(challenge.unwrap(), req.user!.id.id, `preview-sign:enroll:${proof.registration.id}`);
		if (challenge.unwrap().challenge.toString('base64url') !== proof.challenge) throw new Error('Enrollment proof challenge mismatch');
		const seed = await AppDataSource.transaction('READ COMMITTED', async (manager) => {
			const passkey = await lockSharedCredential(manager, proof.registration.webauthnCredentialId, req.user!.id.id);
			if (!passkey || !passkey.prfCapable || passkey.credentialId.toString('base64url') !== proof.registration.credentialId)
				throw new Error('The shared PRF credential was removed or changed');
			const verified = await verifySharedCredentialAssertion(passkey, req.body.credential, {
				challenge: proof.challenge,
				origin: config.webauthn.origin,
				rpId: proof.rpId,
			});
			verifyEnrollmentProofSignature(proof, getSignedPreviewSignature(verified.authenticatorData));
			stage = 'storage';
			const value = proof.registration;
			const record = await manager.save(
				SigningCredentialEntity,
				manager.create(SigningCredentialEntity, {
					id: value.id,
					userUuid: value.userUuid,
					webauthnCredentialId: passkey.id,
					keyHandle: Buffer.from(value.keyHandle, 'base64url'),
					publicSeed: Buffer.from(value.publicSeed, 'base64url'),
					attestation: value.attestation,
				}),
			);
			passkey.signatureCount = verified.newCounter;
			passkey.lastUseTime = new Date();
			passkey.pendingSigningAttestation = null;
			await manager.save(passkey);
			return publicSeed(record, passkey);
		});
		res.send(seed);
	} catch (error) {
		const failure = enrollmentFailure(stage, error);
		console.error('[previewSign] Shared-passkey enrollment failed', failure.log);
		res.status(failure.status).send(failure.body);
	}
});

previewSignRouter.post('/sign-begin', async (req, res) => {
	try {
		if (typeof req.body.seedId !== 'string') return res.sendStatus(400);
		const seed = await repository().findOneBy({
			id: req.body.seedId,
			userUuid: req.user!.id.id,
		});
		if (!seed) return res.sendStatus(404);
		const result = await createChallenge(`preview-sign:${seed.id}`, req.user!.id);
		if (result.err) return res.sendStatus(500);
		res.send({
			challengeId: result.unwrap().id,
			challenge: result.unwrap().challenge,
		});
	} catch {
		res.sendStatus(500);
	}
});

previewSignRouter.post('/sign-finish', async (req, res) => {
	try {
		if (typeof req.body.seedId !== 'string') return res.sendStatus(400);
		const challenge = await popChallenge(req.body.challengeId);
		if (challenge.err) return res.sendStatus(400);
		assertPreviewSignChallenge(challenge.unwrap(), req.user!.id.id, `preview-sign:${req.body.seedId}`);
		const signature = await AppDataSource.transaction('READ COMMITTED', async (manager) => {
			const seed = await manager.findOneBy(SigningCredentialEntity, {
				id: req.body.seedId,
				userUuid: req.user!.id.id,
			});
			if (!seed) throw new Error('Signing seed not found');
			// Same row and lock used by ordinary login and enrollment proof.
			const passkey = await lockSharedCredential(manager, seed.webauthnCredentialId, req.user!.id.id);
			if (!passkey) throw new Error('Shared passkey no longer exists');
			const verified = await verifySharedCredentialAssertion(passkey, req.body.credential, {
				challenge: challenge.unwrap().challenge.toString('base64url'),
				origin: config.webauthn.origin,
				rpId: config.webauthn.rp.id,
			});
			const signature = getSignedPreviewSignature(verified.authenticatorData);
			passkey.signatureCount = verified.newCounter;
			passkey.lastUseTime = new Date();
			await manager.save(passkey);
			return signature;
		});
		res.send({ signature: signature.toString('base64url') });
	} catch {
		res.status(400).send({ error: 'Hardware signing assertion could not be verified' });
	}
});
