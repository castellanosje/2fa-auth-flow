import { Router } from "express";

import {
	refreshToken,
	loginUser,
	registerUser,
	logOutUser,
	gen2Fa,
	validate2Fa,
	login2Fa
} from "../controllers/auth.controllers";

import requireAuth from "../middlewares/requireAuth";

const router = Router();

router.post("/register", registerUser);

router.post('/login',loginUser);

router.post('/refresh-token', refreshToken);

router.get("/2fa/generate", requireAuth, gen2Fa);

router.post("/2fa/validate", requireAuth, validate2Fa);

router.post("/2fa/login", login2Fa);

router.get("/logout", requireAuth, logOutUser);



export default router;



