import express from "express";
import cors from "cors";
import path from "path";
import { config } from "dotenv";

config();

import { connectDB } from "./config/db.js";

import router from "./routes/auth.routes.js";
import moduleRoutes from "./routes/auth.routes.js";

connectDB();

const app = express();


const PORT =
  process.env.PORT || 5000;


app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true,
  })
);

app.use(
  express.json()
);

app.use(
  express.urlencoded({
    extended: true,
  })
);


// Example:
// http://localhost:5000/uploads/modules/image.png

app.use(
  "/uploads",
  express.static(
    path.join(
      process.cwd(),
      "uploads"
    )
  )
);


app.use(
  "/api",
  router
);


app.use(
  "/api",
  moduleRoutes
);

app.get(
  "/",
  (req, res) => {

    res.send(
      "Hello World"
    );

  }
);


app.listen(
  PORT,
  () => {

    console.log(
      `Server is running on port ${PORT}`
    );

  }
);