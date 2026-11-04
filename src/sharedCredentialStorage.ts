import type { EntityManager } from 'typeorm';
import { WebauthnCredentialEntity } from './entities/user.entity';

/** Lock by primary key before checking ownership. A joined locking scan can
 * fail with ER_CHECKREAD in MariaDB when another assertion updates this row.
 * The row stays locked throughout the ownership check and counter update. */
export async function lockSharedCredential(manager: EntityManager, credentialId: string, userId: string) {
	const credential = await manager
		.createQueryBuilder(WebauthnCredentialEntity, 'credential')
		.where('credential.id = :credentialId', { credentialId })
		.setLock('pessimistic_write')
		.getOne();
	if (!credential) return null;
	const owned = await manager
		.createQueryBuilder(WebauthnCredentialEntity, 'credential')
		.innerJoin('credential.user', 'owner')
		.where('credential.id = :credentialId', { credentialId })
		.andWhere('owner.uuid = :userId', { userId })
		.getExists();
	return owned ? credential : null;
}
