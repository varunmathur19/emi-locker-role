import express from "express";

import {
    createuserrole,
    getUsers,
    // getHierarchy,
    getHierarchyById,
    loginUser,
    logoutUser,
    getDropdownUsers,
} from "../controllers/auth.controller.js";
import { authMiddleware } from "../middleware/auth.middleware.js";
import { validationResult } from "express-validator";


const router = express.Router();


// Register User

router.post(
  "/add-staff",
  authMiddleware,
  createuserrole,
);

router.post("/login", loginUser);

// Get All Users
router.get(
    "/getAllStaffData",
    getUsers
);

//hierarchy 
router.get("/all-staff-data/:id", getHierarchyById);

// logout
router.post(
"/logout-staff",
authMiddleware,
logoutUser
);

//User Chain Api
router.get("/hierarchy-dropdown", getDropdownUsers);

export default router;