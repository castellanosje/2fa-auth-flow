import {
	Entity,
	Column,
	PrimaryGeneratedColumn,
	CreateDateColumn,
	UpdateDateColumn,
	BaseEntity,
} from "typeorm";

@Entity()
export class User extends BaseEntity {
	@PrimaryGeneratedColumn()
	id: number;

	@Column({
		unique: true,
	})
	
	userName: string;

	@Column()
	password: string;

	@Column()
	firstName: string;

	@Column()
	email: string;

	@Column()
	lastName: string;

	@Column({
		default: true,
	})
	active: boolean;

	@CreateDateColumn()
	createdAt: Date;

	@UpdateDateColumn()
	updatedAt: Date;
}
