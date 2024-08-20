import { MigrationInterface, QueryRunner } from "typeorm";

export class InvalidAccessTokenEntity1723822674115 implements MigrationInterface {
    name = 'InvalidAccessTokenEntity1723822674115'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`CREATE TABLE "invalid_access_token" ("userId" integer NOT NULL, "accessToken" character varying NOT NULL, "expirationTime" TIMESTAMP NOT NULL, CONSTRAINT "PK_51089eaf36c19777ff729b54beb" PRIMARY KEY ("userId"))`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`DROP TABLE "invalid_access_token"`);
    }

}
