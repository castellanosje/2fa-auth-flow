import express from "express";
import morgan from "morgan";
import cors from "cors";
import userRoutes from "./routes/user.routes";
import authRoutes from "./routes/auth.routes";
const app = express();

// general middlewares
app.use(morgan("dev"));
app.use(cors());
app.use(express.json());

// routes middlewares
app.use('/api/users', userRoutes);
app.use('/api/auth',authRoutes);

export default app;
