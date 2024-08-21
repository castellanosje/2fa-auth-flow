// based on https://www.youtube.com/watch?v=eQ4fBSUI-vw
import { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";
import { JwtPayload } from "jsonwebtoken";
import { InvalidAccessToken } from "../schema/invalidAccessToken.schema";
import dotenv from "dotenv";

dotenv.config();
interface ExtendedJwtPayload extends JwtPayload {
	userId: string;
}

const requireAuth = async (req: Request, res: Response, next: NextFunction) => {
	const accessToken = req.headers.authorization?.split(" ")[1];

	if (!accessToken) {
		return res.status(401).json({ message: "Access denied" });
	}

	if (await InvalidAccessToken.findOne({ where: { accessToken } })) {
		return res.status(401).json({
			message: "Access token expired",
			code: "AccessTokenExpired",
		});
	}

	try {
		const decodedAccessToken = jwt.verify(
			accessToken,
			process.env.ACCESS_TOKEN_SECRET!
		) as ExtendedJwtPayload;

		// for token invalidation in logout function
		req.accessToken = { value: accessToken, exp: decodedAccessToken.exp };

		req.user = {
			id: decodedAccessToken.userId,
		};

		return next();
	} catch (error) {
		if (error instanceof jwt.TokenExpiredError) {
			return res
				.status(401)
				.json({ message: "Access token expired", code: "AccessTokenExpired" });
		} else if (error instanceof jwt.JsonWebTokenError) {
			return res.status(401).json({
				message: "Access token invalid",
				code: "AccessTokenInvalid",
			});
		} else {
			if (error instanceof Error) {
				return res.status(500).json({ message: error.message });
			}
		}
	}
};

export default requireAuth;
