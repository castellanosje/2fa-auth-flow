import { MigrationInterface, QueryRunner } from "typeorm";

export class EmailFieldUser1723665499239 implements MigrationInterface {
    name = 'EmailFieldUser1723665499239'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "user" ADD "email" character varying NOT NULL`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "user" DROP COLUMN "email"`);
    }

}
