import express from "express";

import {
    createuserrole,
    getUsers,
    loginUser,
    logoutUser,
    getDropdownUsers,
    updatedstaffdata,
    getStaffDataById,
    loginAsUser,
} from "../controllers/auth.controller.js";
import { authMiddleware } from "../middleware/auth.middleware.js";
import { validationResult , body } from "express-validator";


const router = express.Router();


// Register Staff

router.post(
  "/add-staff",

  // ==========================================
  // AUTH
  // ==========================================

  authMiddleware,


  // ==========================================
  // ORGANIZATION NAME
  // ==========================================

  body("organization_name")
    .trim()
    .notEmpty()
    .withMessage("Organization Name is required"),


  // ==========================================
  // NAME
  // ==========================================

  body("name")
    .trim()
    .notEmpty()
    .withMessage("Name is required"),


  // ==========================================
  // EMAIL
  // ==========================================

  body("email")
    .trim()
    .notEmpty()
    .withMessage("Email is required")
    .isEmail()
    .withMessage("Please enter a valid email")
    .normalizeEmail(),


  // ==========================================
  // ROLE ID
  // ==========================================

  body("role_id")
    .notEmpty()
    .withMessage("Role ID is required")
    .isInt({ min: 1, max: 9 })
    .withMessage(
      "Role ID must be a number between 1 and 9"
    ),


  // ==========================================
  // PHONE
  // ==========================================

  body("phone")
    .trim()
    .notEmpty()
    .withMessage("Phone is required")
    .matches(/^(?:\+91\s?)?[6-9]\d{9}$/)
    .withMessage(
      "Phone must be a valid 10 digit Indian mobile number"
    ),


  // ==========================================
  // COUNTRY
  // ==========================================

  body("country")
    .trim()
    .notEmpty()
    .withMessage("Country is required"),


  // ==========================================
  // STATE
  // ==========================================

  body("state")
    .trim()
    .notEmpty()
    .withMessage("State is required"),


  // ==========================================
  // CITY
  // ==========================================

  body("city")
    .trim()
    .notEmpty()
    .withMessage("City is required"),


  // ==========================================
  // VALIDATION RESULT
  // ==========================================

  (req, res, next) => {

    const errors = validationResult(req);

    if (!errors.isEmpty()) {

      return res.status(400).json({
        success: false,
        message: "Validation Error",
        errors: errors.array(),
      });

    }

    next();
  },


  // ==========================================
  // CONTROLLER
  // ==========================================

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

//get the data for updated user-staff
router.get(
  "/staff-data/:id",
  getStaffDataById
);

//internal login
router.post("/login-as-user", authMiddleware, loginAsUser);

export default router;