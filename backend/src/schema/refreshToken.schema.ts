import {
	Entity,
	Column,
	BaseEntity,
    PrimaryColumn,
	PrimaryGeneratedColumn,
} from "typeorm";

@Entity()
export class RefreshToken extends BaseEntity {
	@PrimaryGeneratedColumn()
	id: number;

	@Column()
	userId: string;

	@Column()
	refreshToken: string;
}
