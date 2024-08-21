import { MigrationInterface, QueryRunner } from "typeorm";

export class User2fa1724182401571 implements MigrationInterface {
    name = 'User2fa1724182401571'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "user" ADD "twoFaEnabled" boolean NOT NULL`);
        await queryRunner.query(`ALTER TABLE "user" ADD "twoFaSecret" character varying`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "user" DROP COLUMN "twoFaSecret"`);
        await queryRunner.query(`ALTER TABLE "user" DROP COLUMN "twoFaEnabled"`);
    }

}
