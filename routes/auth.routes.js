import express from "express";

import {
    getMasterAdmins,
    createuserrole,
    getUsers
} from "../controllers/auth.controller.js";


const router = express.Router();


// Register User
router.post(
    "/register",
    createuserrole
);


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


export default router;