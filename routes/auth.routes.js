import express from "express";

import {

getMasterAdmins,    
createUser,
getAllUsers
}from "../controllers/auth.controller.js";
import {
    authMiddleware,
isMasterAdmin
}from "../middleware/auth.middleware.js";

const router=express.Router();


//MasterAdmin get api
router.get(
"/master-admins",
getMasterAdmins
);

router.post(
"/create-user",
createUser
);

router.get(
    "/all-users",
    getAllUsers
);





export default router;