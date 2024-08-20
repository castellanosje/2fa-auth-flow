// https://wanago.io/2022/07/25/api-nestjs-database-migrations-typeorm/
import * as dotenv from "dotenv";

dotenv.config();

import { DataSource } from "typeorm";
import { User } from "./schema/user.schema";
import { RefreshToken } from "./schema/refreshToken.schema";
import { EmailFieldUser1723665499239 } from "./migrations/1723665499239-EmailFieldUser";
import { RefreshTokenEntity1723746507490 } from "./migrations/1723746507490-RefreshTokenEntity";
import { InvalidAccessToken } from "./schema/invalidAccessToken.schema";
import { InvalidAccessTokenEntity1723822674115 } from "./migrations/1723822674115-InvalidAccessTokenEntity";
import { RefreshTokenEntityPrimarykey1723822828857 } from "./migrations/1723822828857-RefreshTokenEntity-primarykey";
import { InvalidAccessTokenEntityPrimarykey1723822977766 } from "./migrations/1723822977766-InvalidAccessTokenEntity-primarykey";



export const AppDataSource = new DataSource({
	migrationsTableName: "migrations",
	type: "postgres",
	host: process.env.DBHOST!,
	port: parseInt(process.env.DBPORT!),
	username: "postgres",
	password: "root",
	database: "typeormDB",
	synchronize: false,
	logging: true,
	entities: [User, RefreshToken, InvalidAccessToken],
	migrations: [
		EmailFieldUser1723665499239,
		RefreshTokenEntity1723746507490,
		InvalidAccessTokenEntity1723822674115,
		RefreshTokenEntityPrimarykey1723822828857,
		InvalidAccessTokenEntityPrimarykey1723822977766,
	],
	subscribers: [],
});
