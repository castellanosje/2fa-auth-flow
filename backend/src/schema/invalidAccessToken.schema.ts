import { Entity, Column, BaseEntity, PrimaryColumn, PrimaryGeneratedColumn } from "typeorm";

@Entity()
export class InvalidAccessToken extends BaseEntity {
	@PrimaryGeneratedColumn()
	id: number;

	@Column()
	userId: string;

	@Column()
	accessToken: string;

	@Column()
	expirationTime: Date;
}
