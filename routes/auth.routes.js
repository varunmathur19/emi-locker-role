import express from "express";

import {
    createuserrole,
    getUsers,
    loginUser,
    logoutUser,
    getDropdownUsers,
    updatedstaffdata,
} from "../controllers/auth.controller.js";
import { authMiddleware } from "../middleware/auth.middleware.js";
import { validationResult , body } from "express-validator";


const router = express.Router();


// Register Staff

router.post(
  "/add-staff",
  authMiddleware,
  body("organization_name")
    .trim()
    .notEmpty()
    .withMessage("Organization Name is required"),
  body("name")
    .trim()
    .notEmpty()
    .withMessage("Name is required"),
  body("email")
    .trim()
    .notEmpty()
    .withMessage("Email is required")
    .isEmail()
    .withMessage("Please enter a valid email"),
  body("role_id")
    .trim()
    .notEmpty()
    .withMessage("Role ID is required")
    .isInt({ min: 1, max: 8 })
    .withMessage("Role ID must be a number between 1 and 8"),
  body("phone")
    .trim()
    .notEmpty()
    .withMessage("Phone is required")
    .matches(/^(\+91\s?)?[6-9]\d{9}$/)
    .withMessage("Phone must contain only numbers")
    // .isLength({ min: 10, max: 10 })
    .withMessage("Phone number must be exactly 10 digits"),
  body("country")
    .trim()
    .notEmpty()
    .withMessage("Country is required"),
  body("state")
    .trim()
    .notEmpty()
    .withMessage("State is required"),
  (req,res,next)=>{
    const errors = validationResult(req);
    if(!errors.isEmpty()){
      return res.status(400).json({
        success:false,
        message:"Validation Error",
        errors:errors.array()
      });
    }
  next();
  },
  createuserrole

);

router.post("/login",
    body("email")
     .trim()
     .notEmpty()
    .isEmail()
    .withMessage("Please enter a valid email"),
     body("password")
    .notEmpty()
    .withMessage("Password is required"),

     (req, res, next) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: errors.array().map((error) => error.msg),
      });
    }

    next();
  },
     loginUser
    );

// Get All Users
router.get(
    "/getAllStaffData",
    getUsers
);

// logout
router.post(
"/logout-staff",
authMiddleware,
logoutUser
);

//User Chain Api
router.get("/hierarchy-dropdown", getDropdownUsers);

router.patch("/update-staff-data/:id",updatedstaffdata)

export default router;