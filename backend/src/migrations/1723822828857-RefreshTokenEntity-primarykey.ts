import { MigrationInterface, QueryRunner } from "typeorm";

export class RefreshTokenEntityPrimarykey1723822828857 implements MigrationInterface {
    name = 'RefreshTokenEntityPrimarykey1723822828857'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "refresh_token" ADD "id" SERIAL NOT NULL`);
        await queryRunner.query(`ALTER TABLE "refresh_token" DROP CONSTRAINT "PK_8e913e288156c133999341156ad"`);
        await queryRunner.query(`ALTER TABLE "refresh_token" ADD CONSTRAINT "PK_d84cfdee8317f62504f0260be37" PRIMARY KEY ("userId", "id")`);
        await queryRunner.query(`ALTER TABLE "refresh_token" DROP CONSTRAINT "PK_d84cfdee8317f62504f0260be37"`);
        await queryRunner.query(`ALTER TABLE "refresh_token" ADD CONSTRAINT "PK_b575dd3c21fb0831013c909e7fe" PRIMARY KEY ("id")`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "refresh_token" DROP CONSTRAINT "PK_b575dd3c21fb0831013c909e7fe"`);
        await queryRunner.query(`ALTER TABLE "refresh_token" ADD CONSTRAINT "PK_d84cfdee8317f62504f0260be37" PRIMARY KEY ("userId", "id")`);
        await queryRunner.query(`ALTER TABLE "refresh_token" DROP CONSTRAINT "PK_d84cfdee8317f62504f0260be37"`);
        await queryRunner.query(`ALTER TABLE "refresh_token" ADD CONSTRAINT "PK_8e913e288156c133999341156ad" PRIMARY KEY ("userId")`);
        await queryRunner.query(`ALTER TABLE "refresh_token" DROP COLUMN "id"`);
    }

}
