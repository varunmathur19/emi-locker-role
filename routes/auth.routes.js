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
    getModules,
    updateModule,
    updateUserStatus,
    getAllSubModules,
    updateSubModule,
    getRoles,
    updateProfile,
    getProfiles,
    saveRolePermissions,
    getRolePermissions,
    createProfile
} from "../controllers/auth.controller.js";
import { authMiddleware } from "../middleware/auth.middleware.js";
import { validationResult , body } from "express-validator";
import { uploadModuleIcon , uploadModuleNewIcon } from "../middleware/upload.js";

import { parsePhoneNumberFromString } from "libphonenumber-js";

const router = express.Router();


// Register Staff

router.post(
    "/add-staff",
    authMiddleware,

    body("organization_name")
        .trim()
        .custom((value, { req }) => {
            if (
                Number(req.body.role_id) !== 9 &&
                !value
            ) {
                throw new Error(
                    "Organization Name is required"
                );
            }

            return true;
        }),

    body("name")
        .trim()
        .notEmpty()
        .withMessage("Name is required"),

    body("email")
        .trim()
        .notEmpty()
        .withMessage("Email is required")
        .isEmail()
        .withMessage(
            "Please enter a valid email"
        )
        .normalizeEmail(),

    body("role_id")
        .notEmpty()
        .withMessage("Role ID is required")
        .isInt({ min: 1, max: 9 })
        .withMessage(
            "Role ID must be a number between 1 and 9"
        ),

    body("country")
        .trim()
        .notEmpty()
        .withMessage("Country is required")
        .isLength({ min: 2, max: 2 })
        .withMessage(
            "Country must be a valid country code"
        ),

    body("phone")
        .trim()
        .notEmpty()
        .withMessage("Phone is required")
        .custom((value, { req }) => {
            const country = String(
                req.body.country || ""
            )
                .trim()
                .toUpperCase();

            if (!country) {
                throw new Error(
                    "Country is required for phone validation"
                );
            }

            const phoneNumber =
                parsePhoneNumberFromString(
                    String(value).trim(),
                    country
                );

            if (
                !phoneNumber ||
                !phoneNumber.isValid()
            ) {
                throw new Error(
                    "Phone number is not valid for selected country"
                );
            }

            return true;
        }),

    body("state")
        .trim()
        .notEmpty()
        .withMessage("State is required"),

    body("city")
        .trim()
        .notEmpty()
        .withMessage("City is required"),

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
    authMiddleware,
    getUsers
);

// logout
router.post(
"/logout-staff",
authMiddleware,
logoutUser
);

//User Chain Api
router.get("/hierarchy-dropdown", authMiddleware, getDropdownUsers);

router.patch("/update-staff-data/:id",authMiddleware,updatedstaffdata)

//get the data for updated user-staff
router.get(
  "/staff-data/:id",
  authMiddleware,
  getStaffDataById
);

//internal login
router.post("/login-as-user", authMiddleware, loginAsUser);

router.get(
  "/modules",
  authMiddleware,
  getModules
);

router.put(
  "/update-module/:id",
  authMiddleware,
  uploadModuleNewIcon,
  updateModule
);

router.patch(
  "/user-status",
  authMiddleware,
  updateUserStatus
);


router.get("/sub-modules", authMiddleware,getAllSubModules);

router.put("/sub-modules/:id", authMiddleware, updateSubModule);

router.get("/roles",authMiddleware, getRoles);

//get api for profile data
router.get("/profiles",authMiddleware, getProfiles);

//post api for profile data
router.post("/profiles",authMiddleware, createProfile);

// Edit profile
router.put("/profiles/:id",authMiddleware, updateProfile);

//role-permission
router.post(
  "/role-permissions",
  authMiddleware,
  saveRolePermissions
);
//get role-permission
router.get(
  "/role-permissions/:profile_id",
  authMiddleware,
  getRolePermissions
);







export default router;