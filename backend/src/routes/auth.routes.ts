import { Router } from "express";

import {
	refreshToken,
	loginUser,
	registerUser,
	logOutUser,
} from "../controllers/auth.controllers";
import requireAuth from "../middlewares/requireAuth";

const router = Router();

router.post("/register", registerUser);

router.post('/login',loginUser);

router.post('/refresh-token', refreshToken);

router.get("/logout", requireAuth, logOutUser);

export default router;



