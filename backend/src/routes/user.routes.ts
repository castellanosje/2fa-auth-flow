import { Router } from "express";
import {
	getUsers,
	updateUser,
} from "../controllers/user.controllers";
import requireAuth from "../middlewares/requireAuth";

const router = Router();

router.get("/", requireAuth, getUsers);

router.patch("/:id", requireAuth, updateUser);


export default router;



