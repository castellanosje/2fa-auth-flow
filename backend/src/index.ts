import "reflect-metadata";
import app from "./app";
import { AppDataSource } from "./typeOrm.config";

const main = async () => {
	try {
		await AppDataSource.initialize();
		console.log("Database com initialized");
		app.listen(3000);
		console.log("App running on port: ", 3000);
	} catch (error) {
		console.log("error");
	}
};

main();
