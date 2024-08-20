import { MigrationInterface, QueryRunner } from "typeorm";

export class InvalidAccessTokenEntityPrimarykey1723822977766 implements MigrationInterface {
    name = 'InvalidAccessTokenEntityPrimarykey1723822977766'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "invalid_access_token" ADD "id" SERIAL NOT NULL`);
        await queryRunner.query(`ALTER TABLE "invalid_access_token" DROP CONSTRAINT "PK_51089eaf36c19777ff729b54beb"`);
        await queryRunner.query(`ALTER TABLE "invalid_access_token" ADD CONSTRAINT "PK_e7576485d0849d6f3020b546359" PRIMARY KEY ("userId", "id")`);
        await queryRunner.query(`ALTER TABLE "invalid_access_token" DROP CONSTRAINT "PK_e7576485d0849d6f3020b546359"`);
        await queryRunner.query(`ALTER TABLE "invalid_access_token" ADD CONSTRAINT "PK_b9d61f95302f2838877fa4e938c" PRIMARY KEY ("id")`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "invalid_access_token" DROP CONSTRAINT "PK_b9d61f95302f2838877fa4e938c"`);
        await queryRunner.query(`ALTER TABLE "invalid_access_token" ADD CONSTRAINT "PK_e7576485d0849d6f3020b546359" PRIMARY KEY ("userId", "id")`);
        await queryRunner.query(`ALTER TABLE "invalid_access_token" DROP CONSTRAINT "PK_e7576485d0849d6f3020b546359"`);
        await queryRunner.query(`ALTER TABLE "invalid_access_token" ADD CONSTRAINT "PK_51089eaf36c19777ff729b54beb" PRIMARY KEY ("userId")`);
        await queryRunner.query(`ALTER TABLE "invalid_access_token" DROP COLUMN "id"`);
    }

}
