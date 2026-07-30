import express from "express";

import {
    getMasterAdmins,
    createuserrole,
    getUsers,
    // getHierarchy,
    getHierarchyById,
    loginUser,
    logoutUser,
} from "../controllers/auth.controller.js";
import { authMiddleware } from "../middleware/auth.middleware.js";


const router = express.Router();


// Register User

router.post(
  "/register",
  authMiddleware,
  createuserrole
);

router.post("/login", loginUser);

// Get All Users
router.get(
    "/getAllUser",
    getUsers
);


// Get Master Admins 
router.get(
    "/master-admins",
    getMasterAdmins
);

//hierarchy 
router.get("/hierarchy/:id", getHierarchyById);

// logout
router.post(
"/logout",
authMiddleware,
logoutUser
);

export default router;