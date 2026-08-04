import express from "express";
import cors from "cors";
import { config } from "dotenv";
config();

import { connectDB } from "./config/db.js";
import router from "./routes/auth.routes.js";

connectDB();

const app = express();

const PORT = process.env.PORT;

// Middleware
app.use(
  cors({
    origin: "http://localhost:3000", // Frontend URL
    credentials: true,
  })
);

app.use(express.json());

// Routes
app.use("/api", router);

app.get("/", (req, res) => {
  res.send("Hello World");
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});