import { MigrationInterface, QueryRunner } from "typeorm";

export class RefreshTokenEntity1723746507490 implements MigrationInterface {
    name = 'RefreshTokenEntity1723746507490'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`CREATE TABLE "refresh_token" ("userId" integer NOT NULL, "refreshToken" character varying NOT NULL, CONSTRAINT "PK_8e913e288156c133999341156ad" PRIMARY KEY ("userId"))`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`DROP TABLE "refresh_token"`);
    }

}
