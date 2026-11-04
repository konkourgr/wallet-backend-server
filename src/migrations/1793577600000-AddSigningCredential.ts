import { MigrationInterface, QueryRunner } from "typeorm";

/** Fresh single-key schema. Use a database separate from previewSign. */
export class AddSigningCredential1793577600000 implements MigrationInterface {
	public async up(queryRunner: QueryRunner): Promise<void> {
		await queryRunner.query(
			"ALTER TABLE `webauthn_credential` ADD `pendingSigningAttestation` blob NULL",
		);
		await queryRunner.query(`CREATE TABLE \`signing_credential\` (
			\`id\` varchar(36) NOT NULL,
			\`userUuid\` varchar(36) NOT NULL,
			\`webauthnCredentialId\` varchar(36) NOT NULL,
			\`keyHandle\` blob NOT NULL,
			\`publicSeed\` blob NOT NULL,
			\`attestation\` varchar(6) NOT NULL,
			PRIMARY KEY (\`id\`), UNIQUE INDEX \`UQ_signing_credential_passkey\` (\`webauthnCredentialId\`),
			INDEX \`IDX_signing_credential_user\` (\`userUuid\`),
			CONSTRAINT \`FK_signing_credential_user\` FOREIGN KEY (\`userUuid\`)
				REFERENCES \`user\` (\`webauthnUserHandle\`) ON DELETE CASCADE,
			CONSTRAINT \`FK_signing_credential_passkey\` FOREIGN KEY (\`webauthnCredentialId\`)
				REFERENCES \`webauthn_credential\` (\`id\`) ON DELETE CASCADE
		) ENGINE=InnoDB`);
	}
	public async down(queryRunner: QueryRunner): Promise<void> {
		await queryRunner.query("DROP TABLE `signing_credential`");
		await queryRunner.query(
			"ALTER TABLE `webauthn_credential` DROP COLUMN `pendingSigningAttestation`",
		);
	}
}
