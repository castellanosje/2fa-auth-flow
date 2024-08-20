// based on https://www.youtube.com/watch?v=eQ4fBSUI-vw
import { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";
import { SECRET } from "../authConfig";
import { JwtPayload } from "jsonwebtoken";
import { InvalidAccessToken } from "../schema/invalidAccessToken.schema";

interface ExtendedJwtPayload extends JwtPayload {
	userId: string;
}

const requireAuth = async (req: Request, res: Response, next: NextFunction) => {
	const accessToken = req.headers.authorization?.split(" ")[1];

	// console.log(acessToken);

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
			SECRET
		) as ExtendedJwtPayload;

		// for token invalidation in logout function
		req.accessToken = { value: accessToken, exp: decodedAccessToken.exp };

		// TODO: implement an uuid strategy for user id
		req.user = {
			id: parseInt(decodedAccessToken.userId),
		};

		// console.log(req.user);

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
