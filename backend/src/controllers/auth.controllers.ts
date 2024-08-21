// based on https://www.youtube.com/watch?v=eQ4fBSUI-vw
import { Request, Response } from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { User } from "../schema/user.schema";
import { RefreshToken } from "../schema/refreshToken.schema";
import { JwtPayload } from "jsonwebtoken";
import { AppDataSource } from "../typeOrm.config";
import { InvalidAccessToken } from "../schema/invalidAccessToken.schema";
import dotenv from "dotenv";
import { authenticator } from "otplib";
import qrcode from "qrcode";
import crypto from "crypto";
import NodeCache from "node-cache";

dotenv.config();
const cache = new NodeCache();

export const registerUser = async (req: Request, res: Response) => {
	console.log("body ->", req.body);
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
		user.twoFaEnabled = false;
		user.twoFaSecret = "";

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

		if (user.twoFaEnabled) {
			const tempToken = crypto.randomUUID();
			cache.set(
				process.env.CACHE_TEMPORARY_TOKEN_PREFIX! + tempToken,
				user.id,
				process.env.CACHE_TEMPORARY_TOKEN_TTL!
			);
			return res.status(200).json({
				tempToken,
				expiresInSeconds: process.env.CACHE_TEMPORARY_TOKEN_TTL,
			});
		} else {
			// generate Token
			const accessToken = jwt.sign(
				{ userId: user.id },
				process.env.ACCESS_TOKEN_SECRET!,
				{
					expiresIn: process.env.ACCESS_TOKEN_EXPIRES!,
				}
			);

			const refreshToken = jwt.sign(
				{ userId: user.id },
				process.env.REFRESH_TOKEN_SECRET!,
				{
					expiresIn: process.env.REFRESH_TOKEN_EXPIRES!,
				}
			);

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
		}
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
			process.env.REFRESH_TOKEN_SECRET!
		) as TokenJwtPayload;

		const userRefreshToken = await RefreshToken.findOne({
			where: {
				refreshToken,
				userId: decodedRefreshToken.userId,
			},
		});

		if (!userRefreshToken) {
			return res.status(401).json({ message: "Unauthorized" });
		}

		await RefreshToken.delete({
			userId: decodedRefreshToken.userId,
		});

		const newAccessToken = jwt.sign(
			{ userId: decodedRefreshToken.userId },
			process.env.ACCESS_TOKEN_SECRET!,
			{ subject: "access api", expiresIn: "5m" }
		);

		const newRefreshToken = jwt.sign(
			{ userId: decodedRefreshToken.userId },
			process.env.REFRESH_TOKEN_SECRET!,
			{ subject: "access api", expiresIn: "1w" }
		);

		await RefreshToken.save({
			refreshToken: newRefreshToken,
			userId: decodedRefreshToken.userId,
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
		if (req.user && req.accessToken) {
			await AppDataSource.createQueryBuilder()
				.delete()
				.from(RefreshToken)
				.where({ userId: req.user.id })
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

export const gen2Fa = async (req: Request, res: Response) => {
	try {
		const user = await User.findOne({ where: { id: req.user.id } });
		if (user) {
			const secret = authenticator.generateSecret();
			const uri = authenticator.keyuri(user.email, "my2faApp", secret);

			await User.update({ id: req.user.id }, { twoFaSecret: secret });

			const qrCode = await qrcode.toBuffer(uri, { type: "png", margin: 1 });

			res.setHeader("Content-Disposition", "attachment; filename=qrcode.png");
			return res.status(200).type("image/png").send(qrCode);
		} else {
			return res.status(401).json({ message: "Unauthorized" });
		}
	} catch (error) {
		if (error instanceof Error) {
			return res.status(500).json({
				message: error.message,
			});
		}
	}
};

export const validate2Fa = async (req: Request, res: Response) => {
	try {
		const { totp } = req.body;

		if (!totp) {
			return res.status(422).json({ message: "Unauthorized TOTP is required" });
		}
		const user = await User.findOne({ where: { id: req.user.id } });
		if (user) {
			const verified = authenticator.check(totp, user.twoFaSecret);
			if (!verified) {
				res
					.status(400)
					.json({ message: "Unauthorized TOTP not valid or expired" });
			}
			await User.update({ id: req.user.id }, { twoFaEnabled: true });
			return res.status(200).json({ message: "TOTP validated succesfully" });
		} else {
			return res.status(401).json({ message: "Unauthorized" });
		}
	} catch (error) {
		if (error instanceof Error) {
			return res.status(500).json({
				message: error.message,
			});
		}
	}
};

export const login2Fa = async (req:Request, res:Response) => {
	console.log(req.body, !req.body.tempToken || !req.body.totp);
	try{
		const {tempToken, totp} = req.body;
		if (!tempToken || !totp) {
			return res
				.status(422)
				.json({ message: "Please provide temporary token and TOTP" });
		}
		
		// TODO: double check if there is a different alternative instead of using as string
		const userId = cache.get(
			process.env.CACHE_TEMPORARY_TOKEN_PREFIX! + tempToken
		) as string;

		if(!userId){
			return res.status(401).json({message: "The provided token is incorrect or expired"})
		}

		const user = await User.findOne({ where: { id: userId } });

		if(!user){
			return res.status(401).json({message:"Unauthorized no user found"})
		}

		const verified = authenticator.check(totp, user.twoFaSecret)

		if(!verified){
			return res.status(401).json({ message: "Unauthorized totp invalid" });
		}

		const accessToken = jwt.sign(
			{ userId: user.id },
			process.env.ACCESS_TOKEN_SECRET!,
			{
				expiresIn: process.env.ACCESS_TOKEN_EXPIRES!,
			}
		);

		const refreshToken = jwt.sign(
			{ userId: user.id },
			process.env.REFRESH_TOKEN_SECRET!,
			{
				expiresIn: process.env.REFRESH_TOKEN_EXPIRES!,
			}
		);

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


		
	}catch(error){
		if (error instanceof Error) {
			return res.status(500).json({
				message: error.message,
			});
		}
	}
}