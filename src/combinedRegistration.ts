import { binary } from "./sharedCredential";
import { verifySigningSeedAttestation } from "./previewSign";

/** Both capabilities must have been requested in the SAME registration. */
export function validateCombinedRegistration(
	credential: any,
	signingAttestation: unknown,
	rpId: string,
): Buffer {
	if (credential?.id !== binary(credential.rawId).toString("base64url"))
		throw new Error("Credential ID mismatch");
	if (credential.clientExtensionResults?.prf?.enabled !== true)
		throw new Error(
			"The shared signing passkey must support PRF wallet unlocking",
		);
	const attestation = binary(signingAttestation);
	verifySigningSeedAttestation(
		binary(credential.response.attestationObject),
		attestation,
		binary(credential.response.clientDataJSON),
		rpId,
	);
	return attestation;
}
