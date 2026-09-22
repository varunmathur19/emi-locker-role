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
    createProfile,
    getCountries,
    getStates,
    getCities,
    getKeySettings,
    updateKeySetting,
    getWalletReceiverBalance,
    transferWalletPoints
} from "../controllers/auth.controller.js";
import { authMiddleware } from "../middleware/auth.middleware.js";
import { validationResult , body } from "express-validator";
import { uploadModuleIcon , uploadModuleNewIcon } from "../middleware/upload.js";


import {
  parsePhoneNumberFromString,
} from "libphonenumber-js";

import {
  Country,
} from "country-state-city";

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
        .withMessage("Please enter a valid email")
        .normalizeEmail(),

    body("role_id")
        .notEmpty()
        .withMessage("Role ID is required")
        .isInt({
            min: 1,
            max: 9,
        })
        .withMessage(
            "Role ID must be a number between 1 and 9"
        ),

    body("country")
        .trim()
        .notEmpty()
        .withMessage("Country is required")
        .custom((value) => {
            const country = String(value).trim();

            if (/^\d+$/.test(country)) {
                throw new Error(
                    "Country name is required"
                );
            }

            return true;
        }),

    body("phone")
        .trim()
        .notEmpty()
        .withMessage("Phone is required"),

    body("state")
        .optional({ checkFalsy: true })
        .trim()
        .custom((value) => {
            const state = String(value).trim();

            if (/^\d+$/.test(state)) {
                throw new Error(
                    "State name is required"
                );
            }

            return true;
        }),

    body("city")
        .optional({ checkFalsy: true })
        .trim()
        .custom((value) => {
            const city = String(value).trim();

            if (/^\d+$/.test(city)) {
                throw new Error(
                    "City name is required"
                );
            }

            return true;
        }),

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


//country get api
router.get("/countries", getCountries);

// get state api accoridng to the country
router.get("/states", getStates);

//get city api according to the state
router.get("/cities", getCities);

//get key setting data
router.get(
  "/key-setting",
  authMiddleware,
  getKeySettings
);

//update key setting api
router.put("/key-setting/:id",authMiddleware, updateKeySetting);


//wallet transfer
router.post(
  "/wallet/transfer",
  authMiddleware,
  transferWalletPoints
);


router.get(
  "/wallet/receiver-balance",
  authMiddleware,
  getWalletReceiverBalance
);





export default router;