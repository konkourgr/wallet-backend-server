export type EnrollmentStage =
	| "challenge"
	| "request"
	| "webauthn"
	| "seed_attestation"
	| "proof"
	| "storage";

const failures = {
	challenge: [
		"PREVIEW_SIGN_CHALLENGE_INVALID",
		"Enrollment challenge is invalid or expired. Start enrollment again.",
	],
	request: [
		"PREVIEW_SIGN_REQUEST_INVALID",
		"Hardware signing registration contains invalid WebAuthn data.",
	],
	webauthn: [
		"PREVIEW_SIGN_WEBAUTHN_FAILED",
		"The WebAuthn registration or its attestation could not be verified.",
	],
	seed_attestation: [
		"PREVIEW_SIGN_SEED_ATTESTATION_FAILED",
		"The hardware signing seed attestation could not be verified.",
	],
	proof: [
		"PREVIEW_SIGN_ENROLLMENT_PROOF_FAILED",
		"The hardware signing enrollment test signature could not be verified.",
	],
	storage: [
		"PREVIEW_SIGN_STORAGE_FAILED",
		"The hardware signing registration could not be saved.",
	],
} as const;

/** Avoid serializing DB queries/parameters or entire WebAuthn responses in errors. */
export function enrollmentFailure(
	stage: EnrollmentStage,
	error: unknown,
	production = process.env.NODE_ENV === "production",
) {
	const value = error as {
		code?: unknown;
		driverError?: { code?: unknown };
	} | null;
	const databaseCode = value?.driverError?.code ?? value?.code;
	const missingTable =
		stage === "storage" && databaseCode === "ER_NO_SUCH_TABLE";
	const [code, message] = missingTable
		? [
				"PREVIEW_SIGN_MIGRATION_REQUIRED",
				"The signing credential table is missing. Apply the previewSign database migration.",
			]
		: failures[stage];
	const reason =
		stage !== "storage" && error instanceof Error
			? error.message.replace(/[\r\n]+/g, " ").slice(0, 500)
			: undefined;
	return {
		status: stage === "storage" ? 500 : 400,
		body: {
			error: message,
			code,
			stage,
			...(!production && reason ? { reason } : {}),
		},
		log: {
			stage,
			code,
			...(reason ? { reason } : {}),
			...(typeof databaseCode === "string" && /^[A-Z0-9_]+$/.test(databaseCode)
				? { databaseCode }
				: {}),
		},
	};
}
