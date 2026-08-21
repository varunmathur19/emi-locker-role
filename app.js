import express from "express";
import cors from "cors";
import path from "path";
import { config } from "dotenv";

config();

import { connectDB } from "./config/db.js";

import router from "./routes/auth.routes.js";
import moduleRoutes from "./routes/auth.routes.js";


// =====================================================
// DATABASE
// =====================================================

connectDB();


// =====================================================
// APP
// =====================================================

const app = express();


// =====================================================
// PORT
// =====================================================

const PORT =
  process.env.PORT || 5000;


// =====================================================
// CORS
// =====================================================

app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true,
  })
);


// =====================================================
// BODY PARSER
// =====================================================

app.use(
  express.json()
);

app.use(
  express.urlencoded({
    extended: true,
  })
);


// =====================================================
// STATIC UPLOADS
// =====================================================
//
// Example:
// http://localhost:5000/uploads/modules/image.png
//

app.use(
  "/uploads",
  express.static(
    path.join(
      process.cwd(),
      "uploads"
    )
  )
);


// =====================================================
// AUTH ROUTES
// =====================================================

app.use(
  "/api",
  router
);


// =====================================================
// MODULE ROUTES
// =====================================================
//
// POST:
// /api/add-module
//
// GET:
// /api/modules
//

app.use(
  "/api",
  moduleRoutes
);


// =====================================================
// HOME
// =====================================================

app.get(
  "/",
  (req, res) => {

    res.send(
      "Hello World"
    );

  }
);


// =====================================================
// SERVER
// =====================================================

app.listen(
  PORT,
  () => {

    console.log(
      `Server is running on port ${PORT}`
    );

    console.log(
      `Uploads available at: http://localhost:${PORT}/uploads`
    );

  }
);