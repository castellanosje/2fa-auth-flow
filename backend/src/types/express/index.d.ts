import { JwtPayload } from "jsonwebtoken";
import User from "..";

declare global {
    namespace Express {
        export interface Request {
					user?: User;
					accessToken?:JwtPayload;
				}
    }
}