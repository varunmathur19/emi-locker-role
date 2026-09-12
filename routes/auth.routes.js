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
    getRolePermissions
} from "../controllers/auth.controller.js";
import { authMiddleware } from "../middleware/auth.middleware.js";
import { validationResult , body } from "express-validator";
import { uploadModuleIcon , uploadModuleNewIcon } from "../middleware/upload.js";


const router = express.Router();


// Register Staff

router.post(
    "/add-staff",
    authMiddleware,

    body("organization_name")
        .trim()
        .custom((value, { req }) => {
            if (Number(req.body.role_id) !== 9 && !value) {
                throw new Error("Organization Name is required");
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
        .isInt({ min: 1, max: 9 })
        .withMessage(
            "Role ID must be a number between 1 and 9"
        ),

    body("phone")
        .trim()
        .notEmpty()
        .withMessage("Phone is required")
        .matches(/^(?:\+91\s?)?[6-9]\d{9}$/)
        .withMessage(
            "Phone must be a valid 10 digit Indian mobile number"
        ),

    body("country")
        .trim()
        .notEmpty()
        .withMessage("Country is required"),

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
router.get("/hierarchy-dropdown", getDropdownUsers);

router.patch("/update-staff-data/:id",updatedstaffdata)

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

router.get("/profiles", getProfiles);

// Edit profile
router.put("/profiles/:id", updateProfile);

//role-permission
router.post(
  "/role-permissions",
  authMiddleware,
  saveRolePermissions
);
//get role-permission
router.get(
  "/role-permissions/:profile_id",
  getRolePermissions
);







export default router;