import { Column, Entity, JoinColumn, ManyToOne, PrimaryColumn } from 'typeorm';
import { WebauthnCredentialEntity } from './user.entity';

/** ARKG metadata for an existing login/PRF credential. Public key and counter
 * have one authoritative home in webauthn_credential. */
@Entity({ name: 'signing_credential' })
export class SigningCredentialEntity {
	@PrimaryColumn({ type: 'varchar', length: 36 })
	id!: string;
	@Column({ type: 'varchar', length: 36 })
	userUuid!: string;
	@Column({ type: 'varchar', length: 36, unique: true })
	webauthnCredentialId!: string;
	@ManyToOne(() => WebauthnCredentialEntity, {
		onDelete: 'CASCADE',
		nullable: false,
	})
	@JoinColumn({ name: 'webauthnCredentialId' })
	webauthnCredential!: WebauthnCredentialEntity;
	@Column({ type: 'blob' })
	keyHandle!: Buffer;
	@Column({ type: 'blob' })
	publicSeed!: Buffer;
	@Column({ type: 'varchar', length: 6 })
	attestation!: 'packed' | 'none';
}
