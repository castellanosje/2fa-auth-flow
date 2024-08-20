// based on https://www.youtube.com/watch?v=eQ4fBSUI-vw
import { Request, Response } from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import {
	ACCESS_TOKEN_EXPIRES,
	REFRESH_SECRET,
	REFRESH_TOKEN_EXPIRES,
	SECRET,
} from "../authConfig";
import { User } from "../schema/user.schema";
import { RefreshToken } from "../schema/refreshToken.schema";
import { JwtPayload } from "jsonwebtoken";
import { AppDataSource } from "../typeOrm.config";
import { InvalidAccessToken } from "../schema/invalidAccessToken.schema";

export const registerUser = async (req: Request, res: Response) => {
	console.log("body ->",req.body);
    try {
		const { firstName, lastName, password, userName, email } = req.body;

		if (!userName || !password) {
			return res
				.status(400)
				.json({ message: "you must provide valid credentials" });
		}

		const userExists = await User.findOneBy({ userName });

		if (userExists) {
			return res.status(403).json({ message: "user taken" });
		}

		const user = new User();

		const hashedPassword = await bcrypt.hash(password, 10);

		user.userName = userName;
		user.email = email;
		user.password = hashedPassword;
		user.firstName = firstName;
		user.lastName = lastName;

		await user.save();

		return res.status(200).json(user);
	} catch (error) {
		if (error instanceof Error) {
			return res.status(500).json({ message: error.message });
		}
	}
};

export const loginUser = async (req: Request, res: Response) => {
	try {
		const { userName, password } = req.body;

		const user = await User.findOneBy({ userName });

		if (!user) {
			return res.status(400).json({ message: "invalid credentials" });
		}

		const passwordMatch = await bcrypt.compare(password, user.password);

		if (!passwordMatch) {
			return res.status(400).json({ message: "invalid credentials" });
		}

		// generate Token
		const accessToken = jwt.sign({ userId: user.id }, SECRET, {
			expiresIn: ACCESS_TOKEN_EXPIRES,
		});

		const refreshToken = jwt.sign({ userId: user.id }, REFRESH_SECRET, {
			expiresIn: REFRESH_TOKEN_EXPIRES,
		});

		RefreshToken.save({ refreshToken, userId: user.id });

		return res.status(200).json({
			id: user.id,
			userName: user.userName,
			email: user.email,
			firstName: user.firstName,
			lastName: user.lastName,
			accessToken,
			refreshToken,
		});
	} catch (error) {
		if (error instanceof Error) {
			return res.status(500).json({
				message: error.message,
			});
		}
	}
};

interface TokenJwtPayload extends JwtPayload {
	userId: string;
}

export const refreshToken = async (req: Request, res: Response) => {
	try {
		const { refreshToken } = req.body;

		if (!refreshToken) {
			return res.status(401).json({ message: "Unauthorized" });
		}

		const decodedRefreshToken = jwt.verify(
			refreshToken,
			REFRESH_SECRET
		) as TokenJwtPayload;

		const userRefreshToken = await RefreshToken.findOne({
			where: {
				refreshToken,
				userId: parseInt(decodedRefreshToken.userId),
			},
		});

		if (!userRefreshToken) {
			return res.status(401).json({ message: "Unauthorized" });
		}

		await RefreshToken.delete({
			userId: parseInt(decodedRefreshToken.userId),
		});

		const newAccessToken = jwt.sign(
			{ userId: decodedRefreshToken.userId },
			SECRET,
			{ subject: "access api", expiresIn: "5m" }
		);

		const newRefreshToken = jwt.sign(
			{ userId: decodedRefreshToken.userId },
			REFRESH_SECRET,
			{ subject: "access api", expiresIn: "1w" }
		);

		await RefreshToken.save({
			refreshToken: newRefreshToken,
			userId: parseInt(decodedRefreshToken.userId),
		});

		res.status(200).json({
			accessToken: newAccessToken,
			refreshToken: newRefreshToken,
		});
	} catch (error) {
		if (
			error instanceof jwt.TokenExpiredError ||
			error instanceof jwt.JsonWebTokenError
		) {
			return res.status(401).json({
				message: "Unauthorized",
			});
		} else {
			if (error instanceof Error) {
				return res.status(500).json({
					message: error.message,
				});
			}
		}
	}
};

export const logOutUser = async (req: Request, res: Response) => {
	try {
        console.log(req?.user);
        if (req?.user && req?.accessToken) {
					await AppDataSource.createQueryBuilder()
						.delete()
						.from(RefreshToken)
						.where("userId = :id", { id: req.user.id })
						.execute();

					// TODO: create a cron job to delete expired tokens 
                    // where expiration date is less than current date

                    const tokenExpirationDate = new Date(req.accessToken.exp!);

					await InvalidAccessToken.save({
						accessToken: req.accessToken.value,
						userId: req.user.id,
						expirationTime: tokenExpirationDate,
					});
					return res.status(204).send();
				} else {
					return res.status(400).json({ message: "user not logged in" });
				}
		
	} catch (error) {
		if (error instanceof Error) {
			return res.status(500).json({
				message: error.message,
			});
		}
	}
};
