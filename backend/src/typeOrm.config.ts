// https://wanago.io/2022/07/25/api-nestjs-database-migrations-typeorm/
import * as dotenv from "dotenv";

dotenv.config();

import { DataSource } from "typeorm";
import { User } from "./schema/user.schema";
import { RefreshToken } from "./schema/refreshToken.schema";
import { InvalidAccessToken } from "./schema/invalidAccessToken.schema";
import { User2fa1724182401571 } from "./migrations/1724182401571-user2fa";



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
	migrations: [User2fa1724182401571],
	subscribers: [],
});
