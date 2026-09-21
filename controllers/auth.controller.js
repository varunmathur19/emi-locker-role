import bcrypt from "bcrypt";

import {
    findUserByEmail,
    createUser as createUserModel,
    getAllUsers,
    findUserById, 
    getAllHierarchyUsers,
} from "../models/user.model.js";
import db from "../config/db.js";
import { isValidRole } from "../constants/roles.js";
import jwt from "jsonwebtoken";
import { ROLES } from "../constants/roles.js";
import fs from "fs";
import path from "path";
import { parsePhoneNumberFromString } from "libphonenumber-js";

const isPermissionEnabled = (value) => {
    if (typeof value === "boolean") return value;
    if (typeof value === "number") return value === 1;
    if (typeof value === "string") {
        return value === "1" || value.toLowerCase() === "true";
    }
    if (value && typeof value === "object") {
        if (value.status !== undefined) return Number(value.status) === 1;
        if (value.view !== undefined) return Number(value.view) === 1;
        if (value.access !== undefined) return Number(value.access) === 1;
        return true;
    }
    return false;
};

const getStaffPermissions = async (user) => {
    if (Number(user?.role_id) !== ROLES.STAFF || !user?.role_permission_id) {
        return null;
    }

    const rolePermission = await db("role_permission")
        .select("permission")
        .where("id", Number(user.role_permission_id))
        .first();

    if (!rolePermission?.permission) return null;

    try {
        const permission = typeof rolePermission.permission === "string"
            ? JSON.parse(rolePermission.permission)
            : rolePermission.permission;
        return permission && typeof permission === "object" && !Array.isArray(permission)
            ? permission
            : null;
    } catch {
        return null;
    }
};

const hasStaffRolePermission = (permissions, role, action = null) => {
    if (!permissions || !role) return false;

    const keys = [role.slug, role.name]
        .filter(Boolean)
        .map((value) => String(value).trim().toLowerCase());

    return keys.some((key) => {
        if (action) {
            return isPermissionEnabled(permissions[`${key}.${action}`]) ||
                isPermissionEnabled(permissions[`${key}.manage`]) ||
                // Kept for old profiles which used a role-level permission.
                isPermissionEnabled(permissions[key]);
        }

        return Object.keys(permissions).some((permissionKey) => {
            const normalizedKey = String(permissionKey).trim().toLowerCase();
            return (normalizedKey === key || normalizedKey.startsWith(`${key}.`)) &&
                isPermissionEnabled(permissions[permissionKey]);
        });
    });
};

const getRoleForPermission = (roleId) =>
    db("roles").select("role_id", "name", "slug").where("role_id", Number(roleId)).first();

// ADD STAFF




export const createuserrole = async (req, res) => {
    try {
        const {
            organization_name,
            role_id,
            profile_id,
            name,
            email,
            phone,
            password,
            confirm_password,
            company_address,
            country,
            country_code,
            state,
            city,
            parent_id,
            new_device,
            old_device,
            supreme_device,
            pro_star,
            lite,
            google_tv,
            supreme_lock,
            role_permission,
        } = req.body;

        // --------------------------------------------------
        // BASIC VALIDATION
        // --------------------------------------------------

        if (
            !name ||
            !email ||
            !phone ||
            !password ||
            !confirm_password
        ) {
            return res.status(400).json({
                success: false,
                message:
                    "Name, email, phone, password and confirm password are required",
            });
        }

        if (password !== confirm_password) {
            return res.status(400).json({
                success: false,
                message: "Password and confirm password do not match",
            });
        }

        if (!/^[A-Z]/.test(password)) {
            return res.status(400).json({
                success: false,
                message:
                    "Password must start with a capital letter",
            });
        }

        if (!req.user?.id) {
            return res.status(401).json({
                success: false,
                message: "Unauthorized",
            });
        }

        const created_by = Number(req.user.id);
        const requestedRoleId = Number(role_id);

        // --------------------------------------------------
        // ROLE VALIDATION
        // --------------------------------------------------

        if (
            !Number.isInteger(requestedRoleId) ||
            requestedRoleId < 1 ||
            requestedRoleId > 9
        ) {
            return res.status(400).json({
                success: false,
                message: "Valid role_id is required",
            });
        }

        // --------------------------------------------------
        // GET CREATOR
        // --------------------------------------------------

        const creator = await db("users")
            .where("id", created_by)
            .first();

        if (!creator) {
            return res.status(404).json({
                success: false,
                message: "Creator not found",
            });
        }

        const creatorRole = Number(creator.role_id);

        // --------------------------------------------------
        // ROLE CREATION ACCESS
        // --------------------------------------------------

        if (
            creatorRole !== ROLES.STAFF &&
            creatorRole !== 8 &&
            requestedRoleId !== 9 &&
            requestedRoleId <= creatorRole
        ) {
            return res.status(403).json({
                success: false,
                message:
                    "You are not allowed to create this role",
            });
        }

        if (creatorRole === 8) {
            return res.status(403).json({
                success: false,
                message: "Employee cannot create users",
            });
        }

        // --------------------------------------------------
        // STAFF PERMISSION CHECK
        // --------------------------------------------------

        if (creatorRole === ROLES.STAFF) {
            const [permissions, requestedRole] =
                await Promise.all([
                    getStaffPermissions(creator),
                    getRoleForPermission(requestedRoleId),
                ]);

            if (
                !hasStaffRolePermission(
                    permissions,
                    requestedRole,
                    "add"
                )
            ) {
                return res.status(403).json({
                    success: false,
                    message:
                        "You are not allowed to create this role",
                });
            }
        }

        // --------------------------------------------------
        // PARENT USER
        // --------------------------------------------------

        let finalParentId = null;

        // Staff will always be created under logged-in user
        if (requestedRoleId === 9) {
            finalParentId = created_by;
        } else if (
            parent_id !== undefined &&
            parent_id !== null &&
            parent_id !== ""
        ) {
            const parsedParentId = Number(parent_id);

            if (
                !Number.isInteger(parsedParentId) ||
                parsedParentId <= 0
            ) {
                return res.status(400).json({
                    success: false,
                    message: "Invalid parent_id",
                });
            }

            const parentUser = await db("users")
                .where("id", parsedParentId)
                .first();

            if (!parentUser) {
                return res.status(404).json({
                    success: false,
                    message: "Selected parent not found",
                });
            }

            finalParentId = parsedParentId;
        }

        // --------------------------------------------------
        // EMAIL VALIDATION
        // --------------------------------------------------

        const normalizedEmail = String(email)
            .trim()
            .toLowerCase();

        const existingEmail = await db("users")
            .where("email", normalizedEmail)
            .first();

        if (existingEmail) {
            return res.status(409).json({
                success: false,
                message: "Email already exists",
            });
        }

        // --------------------------------------------------
        // COUNTRY VALIDATION
        // --------------------------------------------------

        const selectedCountry = String(country || "").trim();

        if (!selectedCountry) {
            return res.status(400).json({
                success: false,
                message: "Country is required",
            });
        }

        if (/^\d+$/.test(selectedCountry)) {
            return res.status(400).json({
                success: false,
                message: "Country name is required",
            });
        }

        // --------------------------------------------------
        // PHONE VALIDATION
        // --------------------------------------------------

        const rawPhone = String(phone || "").trim();

        if (!rawPhone) {
            return res.status(400).json({
                success: false,
                message: "Phone number is required",
            });
        }

        let selectedCountryCode = String(
            country_code || ""
        )
            .trim()
            .toUpperCase();

        const countryCodeMap = {
            INDIA: "IN",
            "UNITED STATES": "US",
            "UNITED STATES OF AMERICA": "US",
            USA: "US",
            CANADA: "CA",
            "UNITED KINGDOM": "GB",
            UK: "GB",
            AUSTRALIA: "AU",
            UAE: "AE",
            "UNITED ARAB EMIRATES": "AE",
            SINGAPORE: "SG",
            GERMANY: "DE",
            FRANCE: "FR",
            ITALY: "IT",
            SPAIN: "ES",
            JAPAN: "JP",
            CHINA: "CN",
            "NEW ZEALAND": "NZ",
            "SOUTH AFRICA": "ZA",
        };

        if (!selectedCountryCode) {
            const normalizedCountryName =
                selectedCountry
                    .replace(/\s+/g, " ")
                    .trim()
                    .toUpperCase();

            selectedCountryCode =
                countryCodeMap[normalizedCountryName] || "";
        }

        let parsedPhone = null;

        try {
            if (rawPhone.startsWith("+")) {
                parsedPhone =
                    parsePhoneNumberFromString(rawPhone);

                if (parsedPhone?.country) {
                    selectedCountryCode =
                        parsedPhone.country;
                }
            } else if (selectedCountryCode) {
                parsedPhone =
                    parsePhoneNumberFromString(
                        rawPhone,
                        selectedCountryCode
                    );
            }
        } catch (error) {
            parsedPhone = null;
        }

        if (!parsedPhone || !parsedPhone.isValid()) {
            return res.status(400).json({
                success: false,
                message:
                    "Invalid phone number for selected country",
            });
        }

        const normalizedPhone = parsedPhone.number;

        const existingPhone = await db("users")
            .where("phone", normalizedPhone)
            .first();

        if (existingPhone) {
            return res.status(409).json({
                success: false,
                message: "Phone number already exists",
            });
        }

        // --------------------------------------------------
        // ROLE PERMISSION
        //
        // profiles
        //      ↓
        // role_permission
        //      ↓
        // users.role_permission_id
        // --------------------------------------------------

        let rolePermissionId = null;
        let selectedProfileId = null;
        let permissionData = {};

        if (requestedRoleId === 9) {
            selectedProfileId = Number(profile_id);

            if (
                !Number.isInteger(selectedProfileId) ||
                selectedProfileId <= 0
            ) {
                return res.status(400).json({
                    success: false,
                    message: "Profile is required for Staff",
                });
            }

            // ----------------------------------------------
            // CHECK PROFILE
            // ----------------------------------------------

            const profile = await db("profile")
                .where("id", selectedProfileId)
                .where("status", 1)
                .first();

            if (!profile) {
                return res.status(404).json({
                    success: false,
                    message: "Active profile not found",
                });
            }

            // ----------------------------------------------
            // PARSE PERMISSION
            // ----------------------------------------------

            if (
                role_permission !== undefined &&
                role_permission !== null &&
                role_permission !== ""
            ) {
                if (typeof role_permission === "string") {
                    try {
                        permissionData =
                            JSON.parse(role_permission);
                    } catch (error) {
                        return res.status(400).json({
                            success: false,
                            message:
                                "Invalid role_permission format",
                        });
                    }
                } else {
                    permissionData = role_permission;
                }

                if (
                    typeof permissionData !== "object" ||
                    Array.isArray(permissionData)
                ) {
                    return res.status(400).json({
                        success: false,
                        message:
                            "role_permission must be a valid object",
                    });
                }
            }

            // ----------------------------------------------
            // FIND ROLE PERMISSION BY PROFILE
            // ----------------------------------------------

            const existingRolePermission =
                await db("role_permission")
                    .where(
                        "profile_id",
                        selectedProfileId
                    )
                    .first();

            if (existingRolePermission) {
                // Existing role_permission belongs to this profile.
                // Reuse its ID.
                rolePermissionId =
                    existingRolePermission.id;

                // Only update permission when permission
                // was explicitly provided.
                if (
                    role_permission !== undefined &&
                    role_permission !== null &&
                    role_permission !== ""
                ) {
                    await db("role_permission")
                        .where(
                            "id",
                            existingRolePermission.id
                        )
                        .update({
                            permission:
                                JSON.stringify(
                                    permissionData
                                ),
                            updated_at: db.fn.now(),
                        });
                }
            } else {
                // ------------------------------------------
                // CREATE NEW ROLE PERMISSION
                // ------------------------------------------

                const [newRolePermissionId] =
                    await db("role_permission").insert({
                        profile_id: selectedProfileId,
                        permission:
                            JSON.stringify(
                                permissionData
                            ),
                        created_at: db.fn.now(),
                        updated_at: db.fn.now(),
                    });

                rolePermissionId =
                    newRolePermissionId;
            }
        }

        // --------------------------------------------------
        // RETAILER DEVICE VALIDATION
        // --------------------------------------------------

        if (requestedRoleId === 6) {
            const devices = [
                new_device,
                old_device,
                supreme_device,
                pro_star,
                lite,
                google_tv,
                supreme_lock,
            ];

            const hasDevicePermission =
                devices.some(
                    (value) => Number(value) === 1
                );

            if (!hasDevicePermission) {
                return res.status(400).json({
                    success: false,
                    message:
                        "At least one device permission is required for Retailer",
                });
            }
        }

        // --------------------------------------------------
        // HASH PASSWORD
        // --------------------------------------------------

        const hashedPassword =
            await bcrypt.hash(password, 10);

        // --------------------------------------------------
        // ORGANIZATION NAME
        // --------------------------------------------------

        const finalOrganizationName =
            requestedRoleId === 9
                ? creator.organization_name || null
                : organization_name
                    ? String(organization_name).trim()
                    : null;

        // --------------------------------------------------
        // USER DATA
        // --------------------------------------------------

        const userData = {
            organization_name:
                finalOrganizationName,

            role_id: requestedRoleId,

            // IMPORTANT:
            // Only role_permission_id is stored in users.
            // profile_id is NOT stored in users.
            role_permission_id:
                requestedRoleId === 9
                    ? rolePermissionId
                    : null,

            parent_id: finalParentId,

            name: String(name).trim(),

            email: normalizedEmail,

            phone: normalizedPhone,

            password: hashedPassword,

            company_address:
                company_address
                    ? String(company_address).trim()
                    : null,

            country: selectedCountry,

            state: state
                ? String(state).trim()
                : null,

            city: city
                ? String(city).trim()
                : null,

            new_device:
                Number(new_device) || 0,

            old_device:
                Number(old_device) || 0,

            supreme_device:
                Number(supreme_device) || 0,

            pro_star:
                Number(pro_star) || 0,

            lite:
                Number(lite) || 0,

            google_tv:
                Number(google_tv) || 0,

            supreme_lock:
                Number(supreme_lock) || 0,

            created_by,
        };

        // --------------------------------------------------
        // CREATE USER
        // --------------------------------------------------

        const userId =
            await createUserModel(userData);

        // --------------------------------------------------
        // RESPONSE
        // --------------------------------------------------

        return res.status(201).json({
            success: true,
            message: "User created successfully",

            data: {
                id: userId,

                role_id: requestedRoleId,

                profile_id:
                    requestedRoleId === 9
                        ? selectedProfileId
                        : null,

                role_permission_id:
                    requestedRoleId === 9
                        ? rolePermissionId
                        : null,

                parent_id: finalParentId,

                organization_name:
                    finalOrganizationName,

                name: String(name).trim(),

                email: normalizedEmail,

                phone: normalizedPhone,

                country: selectedCountry,

                country_code:
                    selectedCountryCode,

                state: state
                    ? String(state).trim()
                    : null,

                city: city
                    ? String(city).trim()
                    : null,
            },
        });
    } catch (error) {
        console.error(
            "CREATE USER ROLE ERROR:",
            error
        );

        return res.status(500).json({
            success: false,
            message: "Internal server error",
            error: error.message,
        });
    }
};



// Login staff
export const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    // ==========================================
    // VALIDATION
    // ==========================================

    if (!email || !String(email).trim()) {
      return res.status(400).json({
        success: false,
        message: "Email is required",
      });
    }

    if (!password) {
      return res.status(400).json({
        success: false,
        message: "Password is required",
      });
    }

    // ==========================================
    // FIND USER
    // ==========================================

    const user = await findUserByEmail(
      String(email).trim().toLowerCase()
    );

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // ==========================================
    // ACCOUNT STATUS
    // ==========================================

    if (Number(user.userStatus) === 0) {
      return res.status(403).json({
        success: false,
        message: "Your account is inactive",
      });
    }

    // ==========================================
    // PASSWORD CHECK
    // ==========================================

    const passwordMatch = await bcrypt.compare(
      password,
      user.password
    );

    if (!passwordMatch) {
      return res.status(401).json({
        success: false,
        message: "Invalid password",
      });
    }

    // ==========================================
    // STAFF PERMISSION
    // ==========================================

    let staffPermission = null;

    const isStaff = Number(user.role_id) === 9;

    if (isStaff && user.role_permission_id) {
      const rolePermission = await db("role_permission")
        .select(
          "id",
          "profile_id",
          "permission"
        )
        .where(
          "id",
          Number(user.role_permission_id)
        )
        .first();

      if (rolePermission) {
        let permission =
          rolePermission.permission;

        // Convert JSON string to object
        if (typeof permission === "string") {
          try {
            permission = JSON.parse(permission);
          } catch (error) {
            console.error(
              "STAFF PERMISSION PARSE ERROR:",
              error
            );

            permission = {};
          }
        }

        // Ensure permission is always an object
        if (
          !permission ||
          typeof permission !== "object" ||
          Array.isArray(permission)
        ) {
          permission = {};
        }

        staffPermission = {
          id: rolePermission.id,
          profile_id: rolePermission.profile_id,
          permission,
        };
      }
    }

    // ==========================================
    // JWT TOKEN
    // ==========================================

    const token = jwt.sign(
      {
        id: user.id,
        role_id: user.role_id,
        email: user.email,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "7d",
      }
    );

    // ==========================================
    // USER RESPONSE
    // ==========================================

    const userResponse = {
      id: user.id,
      name: user.name,
      email: user.email,
      role_id: user.role_id,
      userStatus: Number(user.userStatus),

      parent_id: user.parent_id,

      parent_admin_id:
        user.parent_admin_id,

      parent_cnf_id:
        user.parent_cnf_id,

      parent_super_distributor_id:
        user.parent_super_distributor_id,

      parent_distributor_id:
        user.parent_distributor_id,

      parent_fos_id:
        user.parent_fos_id,

      parent_retailer_id:
        user.parent_retailer_id,

      parent_employee_id:
        user.parent_employee_id,

      parent_staff_id:
        user.parent_staff_id,

      // ========================================
      // STAFF PERMISSION ONLY
      // ========================================

      role_permission_id: isStaff
        ? user.role_permission_id
        : null,

      staff_permission: isStaff
        ? staffPermission
        : null,
    };

    // ==========================================
    // LOGIN RESPONSE
    // ==========================================

    return res.status(200).json({
      success: true,
      message: "Login Successful",
      token,
      user: userResponse,
    });
  } catch (error) {
    console.error(
      "LOGIN ERROR:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        error.message ||
        "Internal server error",
    });
  }
};
// GET ALL USERS
export const getUsers = async (req, res) => {
    try {
        const page = Math.max(
            Number(req.query.page) || 1,
            1
        );

        const limit = Math.max(
            Number(req.query.limit) || 10,
            1
        );

        const offset = (page - 1) * limit;

        // --------------------------------------------------
        // ROLE FILTER
        // --------------------------------------------------

        let role_id = null;

        if (
            req.query.role_id !== undefined &&
            String(req.query.role_id).trim() !== ""
        ) {
            role_id = Number(req.query.role_id);

            if (!Number.isInteger(role_id)) {
                return res.status(400).json({
                    success: false,
                    message: "Invalid role_id",
                });
            }
        }

        // --------------------------------------------------
        // SEARCH
        // --------------------------------------------------

        const search =
            req.query.search !== undefined &&
            String(req.query.search).trim() !== ""
                ? String(req.query.search).trim()
                : null;

        // --------------------------------------------------
        // LOCATION FILTERS
        // --------------------------------------------------

        const country =
            req.query.country !== undefined &&
            String(req.query.country).trim() !== ""
                ? String(req.query.country).trim()
                : null;

        const state =
            req.query.state !== undefined &&
            String(req.query.state).trim() !== ""
                ? String(req.query.state).trim()
                : null;

        const city =
            req.query.city !== undefined &&
            String(req.query.city).trim() !== ""
                ? String(req.query.city).trim()
                : null;

        // --------------------------------------------------
        // STATUS FILTER
        // --------------------------------------------------

        let status = null;

        if (
            req.query.status !== undefined &&
            String(req.query.status).trim() !== ""
        ) {
            const statusValue = String(req.query.status)
                .trim()
                .toLowerCase();

            if (
                statusValue === "active" ||
                statusValue === "1"
            ) {
                status = 1;
            } else if (
                statusValue === "inactive" ||
                statusValue === "0"
            ) {
                status = 0;
            } else {
                return res.status(400).json({
                    success: false,
                    message: "Invalid status",
                });
            }
        }

        // --------------------------------------------------
        // LOGGED-IN USER
        // --------------------------------------------------

        const loggedInUserId = Number(req.user?.id);
        const loggedInRoleId = Number(req.user?.role_id);

        if (
            !Number.isInteger(loggedInUserId) ||
            loggedInUserId <= 0
        ) {
            return res.status(401).json({
                success: false,
                message: "Unauthorized user",
            });
        }

        if (!Number.isInteger(loggedInRoleId)) {
            return res.status(401).json({
                success: false,
                message:
                    "Invalid logged-in user role",
            });
        }

        // --------------------------------------------------
        // STAFF ROLE ACCESS
        // --------------------------------------------------

        let staffRoleAccess = false;

        if (loggedInRoleId === ROLES.STAFF) {
            if (role_id === null) {
                return res.status(403).json({
                    success: false,
                    message:
                        "Staff must select an authorized role",
                });
            }

            const [
                staffUser,
                requestedRole,
            ] = await Promise.all([
                db("users")
                    .select(
                        "id",
                        "role_id",
                        "role_permission_id"
                    )
                    .where(
                        "id",
                        loggedInUserId
                    )
                    .first(),

                getRoleForPermission(role_id),
            ]);

            if (!staffUser) {
                return res.status(404).json({
                    success: false,
                    message:
                        "Logged-in staff user not found",
                });
            }

            const permissions =
                await getStaffPermissions(
                    staffUser
                );

            if (
                !hasStaffRolePermission(
                    permissions,
                    requestedRole
                )
            ) {
                return res.status(403).json({
                    success: false,
                    message:
                        "You are not allowed to access this role",
                });
            }

            staffRoleAccess = true;
        }

        // --------------------------------------------------
        // GET USERS
        // --------------------------------------------------

        const result = await getAllUsers(
            limit,
            offset,
            role_id,
            loggedInUserId,
            loggedInRoleId,
            search,
            country,
            state,
            city,
            status,
            staffRoleAccess
        );

        // --------------------------------------------------
        // FORMAT USERS
        // --------------------------------------------------

        const users = await Promise.all(
            result.users.map(async (user) => {
                // ------------------------------------------
                // PARSE ROLE PERMISSION
                // ------------------------------------------

                let parsedPermission = {};

                if (user.role_permission) {
                    try {
                        parsedPermission =
                            typeof user.role_permission ===
                            "string"
                                ? JSON.parse(
                                      user.role_permission
                                  )
                                : user.role_permission;

                        if (
                            !parsedPermission ||
                            typeof parsedPermission !==
                                "object" ||
                            Array.isArray(
                                parsedPermission
                            )
                        ) {
                            parsedPermission = {};
                        }
                    } catch (error) {
                        parsedPermission = {};
                    }
                }

                // ------------------------------------------
                // DEFAULT PARENT DATA
                // ------------------------------------------

                let parent_name =
                    user.parent_name || null;

                let parent_organization_name =
                    user.parent_organization_name ||
                    null;

                // ------------------------------------------
                // CNF PARENT
                // ROLE 2 = CNF
                // ------------------------------------------

                if (
                    Number(user.role_id) === 2 &&
                    user.parent_id
                ) {
                    try {
                        const parentUser =
                            await db("users")
                                .select(
                                    "name",
                                    "organization_name"
                                )
                                .where(
                                    "id",
                                    Number(
                                        user.parent_id
                                    )
                                )
                                .first();

                        if (parentUser) {
                            parent_name =
                                parentUser.name ||
                                null;

                            parent_organization_name =
                                parentUser.organization_name ||
                                null;
                        }
                    } catch (parentError) {
                        console.error(
                            "CNF PARENT FETCH ERROR:",
                            parentError
                        );
                    }
                }

                // ------------------------------------------
                // FINAL USER
                // ------------------------------------------

                return {
                    ...user,

                    parent_name,

                    parent_organization_name,

                    // --------------------------------------
                    // ROLE PERMISSION
                    // --------------------------------------

                    role_permission: {
                        id:
                            user.role_permission_id ||
                            null,

                        profile_id:
                            user.profile_id ||
                            null,

                        profile_name:
                            user.profile_name ||
                            null,

                        permission:
                            parsedPermission,
                    },
                };
            })
        );

        // --------------------------------------------------
        // RESPONSE
        // --------------------------------------------------

        return res.status(200).json({
            success: true,

            pagination: {
                currentPage: page,

                totalPages:
                    Math.ceil(
                        result.total / limit
                    ),

                limit,

                totalUsers:
                    result.total,
            },

            data: users,
        });
    } catch (error) {
        console.error(
            "GET USERS ERROR:",
            error
        );

        return res.status(500).json({
            success: false,
            message:
                error?.message ||
                "Failed to get users",
        });
    }
};

// Logout api
  export const logoutUser = async(req,res)=>{

  try{

      const user = req.user;


      return res.status(200).json({

          success:true,
          message:"Logout Successfully",

          user:{
              // id:user.id,
              // role_id:user.role_id,
              email:user.email
          }

      });


  }
  catch(error){

      return res.status(500).json({

          success:false,
          message:error.message

      });

  }

  };        

// User Chain Api
export const getDropdownUsers = async (req, res) => {
  try {
    const { role_id, parent_id, search, exclude_id } = req.query;

    if (role_id === undefined || role_id === null || role_id === "") {
      return res.status(400).json({
        success: false,
        message: "role_id is required",
      });
    }

    const requestedRoleId = Number(role_id);

    if (
      !Number.isInteger(requestedRoleId) ||
      requestedRoleId < 1 ||
      requestedRoleId > 9
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid role_id",
      });
    }

    let selectedParentId = null;

    if (
      parent_id !== undefined &&
      parent_id !== null &&
      parent_id !== ""
    ) {
      selectedParentId = Number(parent_id);

      if (
        !Number.isInteger(selectedParentId) ||
        selectedParentId <= 0
      ) {
        return res.status(400).json({
          success: false,
          message: "Invalid parent_id",
        });
      }
    }

    let excludeUserId = null;

    if (
      exclude_id !== undefined &&
      exclude_id !== null &&
      exclude_id !== ""
    ) {
      excludeUserId = Number(exclude_id);

      if (
        !Number.isInteger(excludeUserId) ||
        excludeUserId <= 0
      ) {
        return res.status(400).json({
          success: false,
          message: "Invalid exclude_id",
        });
      }
    }

    const searchTerm =
      typeof search === "string" ? search.trim() : "";

    const query = db("users as u")
      .select(
        "u.id",
        "u.organization_name",
        "u.name",
        "u.email",
        "u.phone",
        "u.role_id",
        "u.parent_id",
        "u.created_by",
        "u.created_at"
      )
      .where("u.role_id", requestedRoleId);

    if (selectedParentId !== null) {
      query.where("u.parent_id", selectedParentId);
    }

    if (excludeUserId !== null) {
      query.whereNot("u.id", excludeUserId);
    }

    if (searchTerm) {
      const searchValue = `%${searchTerm}%`;

      query.where(function () {
        this.where("u.name", "like", searchValue)
          .orWhere("u.email", "like", searchValue)
          .orWhere("u.phone", "like", searchValue)
          .orWhere(
            "u.organization_name",
            "like",
            searchValue
          );
      });
    }

    const rows = await query.orderBy([
      { column: "u.name", order: "asc" },
      { column: "u.id", order: "asc" },
    ]);

    return res.status(200).json({
      success: true,
      create_role_id: requestedRoleId,
      parent_id: selectedParentId,
      current_role_id: requestedRoleId,
      current_role_name: getRoleName(requestedRoleId),
      search: searchTerm,
      exclude_id: excludeUserId,
      total: rows.length,
      data: rows,
    });
  } catch (error) {
    console.error("GET DROPDOWN USERS ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to get dropdown users",
      error: error.message,
    });
  }
};

// ROLE NAME
const getRoleName = (roleId) => {

  const roles = {
    1: "Admin",
    2: "CNF",
    3: "Super Distributor",
    4: "Distributor",
    5: "FOS",
    6: "Retailer",
    7: "Employee",
    8: "Staff",
  };

  return (
    roles[roleId] ||
    "User"
  );
};

//upadte staff
export const updatedstaffdata = async (req, res) => {
    try {
        const { id } = req.params;

        // --------------------------------------------------
        // VALIDATE USER ID
        // --------------------------------------------------

        if (!id) {
            return res.status(400).json({
                success: false,
                message: "User ID is required",
            });
        }

        const userId = Number(id);

        if (
            !Number.isInteger(userId) ||
            userId <= 0
        ) {
            return res.status(400).json({
                success: false,
                message: "Invalid User ID",
            });
        }

        // --------------------------------------------------
        // REQUEST DATA
        // --------------------------------------------------

        const {
            organization_name,
            role_id,
            profile_id,
            role_permission,
            name,
            email,
            phone,
            company_address,
            country,
            state,
            city,
            parent_id,
            new_device,
            old_device,
            supreme_device,
            pro_star,
            lite,
            google_tv,
            supreme_lock,
            password,
        } = req.body;

        // --------------------------------------------------
        // GET EXISTING USER
        //
        // IMPORTANT:
        // users.profile_id DOES NOT EXIST.
        // Only role_permission_id is used.
        // --------------------------------------------------

        const existingUser = await db("users")
            .select(
                "id",
                "role_id",
                "parent_id",
                "role_permission_id"
            )
            .where("id", userId)
            .first();

        if (!existingUser) {
            return res.status(404).json({
                success: false,
                message: "User not found",
            });
        }

        // --------------------------------------------------
        // ROLE
        // --------------------------------------------------

        const currentRoleId = Number(
            role_id ?? existingUser.role_id
        );

        if (
            !Number.isInteger(currentRoleId) ||
            currentRoleId < 1 ||
            currentRoleId > 9
        ) {
            return res.status(400).json({
                success: false,
                message: "Invalid role ID",
            });
        }

        // --------------------------------------------------
        // PARENT
        // --------------------------------------------------

        let normalizedParentId =
            existingUser.parent_id ?? null;

        if (parent_id !== undefined) {
            if (
                parent_id === null ||
                parent_id === ""
            ) {
                normalizedParentId = null;
            } else {
                normalizedParentId = Number(
                    parent_id
                );

                if (
                    !Number.isInteger(
                        normalizedParentId
                    ) ||
                    normalizedParentId <= 0
                ) {
                    return res.status(400).json({
                        success: false,
                        message:
                            "Invalid parent ID",
                    });
                }

                if (
                    normalizedParentId === userId
                ) {
                    return res.status(400).json({
                        success: false,
                        message:
                            "User cannot be their own parent",
                    });
                }

                const parentUser = await db("users")
                    .select(
                        "id",
                        "role_id",
                        "name",
                        "organization_name"
                    )
                    .where(
                        "id",
                        normalizedParentId
                    )
                    .first();

                if (!parentUser) {
                    return res.status(400).json({
                        success: false,
                        message:
                            "Selected parent not found",
                    });
                }

                const parentRoleId = Number(
                    parentUser.role_id
                );

                if (
                    parentRoleId >=
                    currentRoleId
                ) {
                    return res.status(400).json({
                        success: false,
                        message:
                            "Selected parent role is invalid",
                    });
                }
            }
        }

        // --------------------------------------------------
        // PROFILE
        //
        // Profile is NOT stored in users.
        //
        // profile_id
        //      ↓
        // role_permission.profile_id
        //      ↓
        // role_permission.id
        //      ↓
        // users.role_permission_id
        // --------------------------------------------------

        const hasProfileId =
            profile_id !== undefined &&
            profile_id !== null &&
            String(profile_id).trim() !== "";

        let normalizedProfileId = null;

        if (hasProfileId) {
            normalizedProfileId = Number(
                profile_id
            );

            if (
                !Number.isInteger(
                    normalizedProfileId
                ) ||
                normalizedProfileId <= 0
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid profile ID",
                });
            }

            const profile = await db("profile")
                .select(
                    "id",
                    "name",
                    "status"
                )
                .where(
                    "id",
                    normalizedProfileId
                )
                .first();

            if (!profile) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Selected profile not found",
                });
            }

            if (Number(profile.status) !== 1) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Selected profile is inactive",
                });
            }
        }

        // --------------------------------------------------
        // ROLE PERMISSION INPUT
        // --------------------------------------------------

        const hasRolePermission =
            role_permission !== undefined &&
            role_permission !== null &&
            role_permission !== "";

        let parsedRolePermission = null;

        if (hasRolePermission) {
            parsedRolePermission =
                role_permission;

            if (
                typeof parsedRolePermission ===
                "string"
            ) {
                try {
                    parsedRolePermission =
                        JSON.parse(
                            parsedRolePermission
                        );
                } catch (error) {
                    return res.status(400).json({
                        success: false,
                        message:
                            "Invalid role_permission JSON",
                    });
                }
            }

            if (
                typeof parsedRolePermission !==
                    "object" ||
                parsedRolePermission === null ||
                Array.isArray(
                    parsedRolePermission
                )
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid role_permission format",
                });
            }
        }

        // --------------------------------------------------
        // TRANSACTION
        // --------------------------------------------------

        const result = await db.transaction(
            async (trx) => {
                /*
                |--------------------------------------------------------------------------
                | KEEP EXISTING ROLE PERMISSION
                |--------------------------------------------------------------------------
                */

                let rolePermissionId =
                    existingUser.role_permission_id ??
                    null;

                /*
                |--------------------------------------------------------------------------
                | PROFILE SELECTED
                |
                | Find role_permission using profile_id.
                |--------------------------------------------------------------------------
                */

                if (hasProfileId) {
                    const profilePermission =
                        await trx(
                            "role_permission"
                        )
                            .select(
                                "id",
                                "profile_id",
                                "permission"
                            )
                            .where(
                                "profile_id",
                                normalizedProfileId
                            )
                            .first();

                    /*
                    |--------------------------------------------------------------------------
                    | EXISTING PROFILE PERMISSION
                    |--------------------------------------------------------------------------
                    */

                    if (profilePermission) {
                        rolePermissionId =
                            profilePermission.id;

                        /*
                        | Only change permission if
                        | permission was explicitly sent.
                        */

                        if (
                            hasRolePermission
                        ) {
                            await trx(
                                "role_permission"
                            )
                                .where(
                                    "id",
                                    profilePermission.id
                                )
                                .update({
                                    permission:
                                        JSON.stringify(
                                            parsedRolePermission
                                        ),
                                    updated_at:
                                        trx.fn.now(),
                                });
                        }
                    } else {
                        /*
                        |--------------------------------------------------------------------------
                        | CREATE NEW PROFILE PERMISSION
                        |--------------------------------------------------------------------------
                        */

                        const inserted =
                            await trx(
                                "role_permission"
                            ).insert({
                                profile_id:
                                    normalizedProfileId,

                                permission:
                                    JSON.stringify(
                                        hasRolePermission
                                            ? parsedRolePermission
                                            : {}
                                    ),

                                created_at:
                                    trx.fn.now(),

                                updated_at:
                                    trx.fn.now(),
                            });

                        rolePermissionId =
                            Number(
                                inserted[0]
                            );
                    }
                }

                /*
                |--------------------------------------------------------------------------
                | NO PROFILE CHANGE
                |
                | But permission explicitly changed.
                |--------------------------------------------------------------------------
                */

                else if (
                    hasRolePermission
                ) {
                    /*
                    | Existing role_permission
                    */

                    if (rolePermissionId) {
                        const permissionRow =
                            await trx(
                                "role_permission"
                            )
                                .where(
                                    "id",
                                    rolePermissionId
                                )
                                .first();

                        if (permissionRow) {
                            await trx(
                                "role_permission"
                            )
                                .where(
                                    "id",
                                    rolePermissionId
                                )
                                .update({
                                    permission:
                                        JSON.stringify(
                                            parsedRolePermission
                                        ),
                                    updated_at:
                                        trx.fn.now(),
                                });
                        } else {
                            /*
                            | Broken reference
                            */

                            const inserted =
                                await trx(
                                    "role_permission"
                                ).insert({
                                    permission:
                                        JSON.stringify(
                                            parsedRolePermission
                                        ),
                                    created_at:
                                        trx.fn.now(),
                                    updated_at:
                                        trx.fn.now(),
                                });

                            rolePermissionId =
                                Number(
                                    inserted[0]
                                );
                        }
                    } else {
                        /*
                        | No permission record
                        */

                        const inserted =
                            await trx(
                                "role_permission"
                            ).insert({
                                permission:
                                    JSON.stringify(
                                        parsedRolePermission
                                    ),
                                created_at:
                                    trx.fn.now(),
                                updated_at:
                                    trx.fn.now(),
                            });

                        rolePermissionId =
                            Number(
                                inserted[0]
                            );
                    }
                }

                // --------------------------------------------------
                // USER UPDATE
                // --------------------------------------------------

                const updateData = {};

                if (
                    organization_name !==
                    undefined
                ) {
                    updateData.organization_name =
                        organization_name;
                }

                if (
                    role_id !== undefined
                ) {
                    updateData.role_id =
                        currentRoleId;
                }

                /*
                |--------------------------------------------------------------------------
                | IMPORTANT:
                | DO NOT update users.profile_id
                |--------------------------------------------------------------------------
                */

                if (name !== undefined) {
                    updateData.name = name;
                }

                if (email !== undefined) {
                    updateData.email = email;
                }

                if (phone !== undefined) {
                    updateData.phone = phone;
                }

                if (
                    company_address !==
                    undefined
                ) {
                    updateData.company_address =
                        company_address;
                }

                if (country !== undefined) {
                    updateData.country =
                        country;
                }

                if (state !== undefined) {
                    updateData.state =
                        state;
                }

                if (city !== undefined) {
                    updateData.city =
                        city;
                }

                // --------------------------------------------------
                // PARENT
                // --------------------------------------------------

                if (
                    parent_id !== undefined
                ) {
                    updateData.parent_id =
                        normalizedParentId;
                }

                // --------------------------------------------------
                // ROLE PERMISSION ID
                // --------------------------------------------------

                if (
                    rolePermissionId !== null
                ) {
                    updateData.role_permission_id =
                        rolePermissionId;
                }

                // --------------------------------------------------
                // DEVICE FLAGS
                // --------------------------------------------------

                if (
                    new_device !== undefined
                ) {
                    updateData.new_device =
                        Number(new_device) || 0;
                }

                if (
                    old_device !== undefined
                ) {
                    updateData.old_device =
                        Number(old_device) || 0;
                }

                if (
                    supreme_device !==
                    undefined
                ) {
                    updateData.supreme_device =
                        Number(
                            supreme_device
                        ) || 0;
                }

                if (
                    pro_star !== undefined
                ) {
                    updateData.pro_star =
                        Number(pro_star) || 0;
                }

                if (lite !== undefined) {
                    updateData.lite =
                        Number(lite) || 0;
                }

                if (
                    google_tv !== undefined
                ) {
                    updateData.google_tv =
                        Number(google_tv) || 0;
                }

                if (
                    supreme_lock !==
                    undefined
                ) {
                    updateData.supreme_lock =
                        Number(
                            supreme_lock
                        ) || 0;
                }

                // --------------------------------------------------
                // PASSWORD
                // --------------------------------------------------

                if (
                    password !== undefined &&
                    password !== null &&
                    password !== ""
                ) {
                    updateData.password =
                        password;
                }

                // --------------------------------------------------
                // UPDATED AT
                // --------------------------------------------------

                updateData.updated_at =
                    trx.fn.now();

                // --------------------------------------------------
                // UPDATE USER
                // --------------------------------------------------

                await trx("users")
                    .where("id", userId)
                    .update(updateData);

                // --------------------------------------------------
                // GET UPDATED USER
                // --------------------------------------------------

                const updatedUser =
                    await trx("users")
                        .select(
                            "id",
                            "organization_name",
                            "role_id",
                            "role_permission_id",
                            "name",
                            "email",
                            "phone",
                            "company_address",
                            "country",
                            "state",
                            "city",
                            "parent_id",
                            "new_device",
                            "old_device",
                            "supreme_device",
                            "pro_star",
                            "lite",
                            "google_tv",
                            "supreme_lock",
                            "created_at",
                            "updated_at"
                        )
                        .where("id", userId)
                        .first();

                // --------------------------------------------------
                // GET ROLE PERMISSION + PROFILE
                // --------------------------------------------------

                let finalRolePermission = null;

                if (
                    updatedUser?.role_permission_id
                ) {
                    const permissionRow =
                        await trx(
                            "role_permission"
                        )
                            .leftJoin(
                                "profile",
                                "role_permission.profile_id",
                                "profile.id"
                            )
                            .select(
                                "role_permission.id",
                                "role_permission.profile_id",
                                "role_permission.permission",
                                "profile.name as profile_name"
                            )
                            .where(
                                "role_permission.id",
                                updatedUser.role_permission_id
                            )
                            .first();

                    if (permissionRow) {
                        let permission =
                            permissionRow.permission;

                        if (
                            typeof permission ===
                            "string"
                        ) {
                            try {
                                permission =
                                    JSON.parse(
                                        permission
                                    );
                            } catch (error) {
                                permission = {};
                            }
                        }

                        finalRolePermission = {
                            id:
                                permissionRow.id,

                            profile_id:
                                permissionRow.profile_id,

                            profile_name:
                                permissionRow.profile_name ||
                                null,

                            permission:
                                permission || {},
                        };
                    }
                }

                // --------------------------------------------------
                // FINAL RESULT
                // --------------------------------------------------

                return {
                    ...updatedUser,

                    role_permission:
                        finalRolePermission,
                };
            }
        );

        // --------------------------------------------------
        // SUCCESS
        // --------------------------------------------------

        return res.status(200).json({
            success: true,
            message:
                "Staff data updated successfully",
            data: result,
        });
    } catch (error) {
        console.error(
            "UPDATE STAFF ERROR:",
            error
        );

        return res.status(500).json({
            success: false,
            message:
                "Failed to update staff data",
            error: error.message,
        });
    }
};

//get staff data with id in edit 
export const getStaffDataById = async (req, res) => {
  try {
    const { id } = req.params;

    if (!id) {
      return res.status(400).json({
        success: false,
        message: "User ID is required",
      });
    }

    const userId = Number(id);

    if (!Number.isInteger(userId) || userId <= 0) {
      return res.status(400).json({
        success: false,
        message: "Invalid User ID",
      });
    }

    /*
    |--------------------------------------------------------------------------
    | GET USER
    |--------------------------------------------------------------------------
    */

    const user = await db({ u: "users" })
      .leftJoin(
        { rp: "role_permission" },
        "rp.id",
        "u.role_permission_id"
      )
      .leftJoin(
        { p: "profile" },
        "p.id",
        "rp.profile_id"
      )
      .select(
        "u.id",
        "u.organization_name",
        "u.role_id",

        // Role Permission
        "u.role_permission_id",

        // Profile
        "p.id as profile_id",
        "p.name as profile_name",
        "p.status as profile_status",

        "u.name",
        "u.email",
        "u.phone",
        "u.company_address",
        "u.country",
        "u.state",
        "u.city",
        "u.parent_id",

        "u.new_device",
        "u.old_device",
        "u.supreme_device",
        "u.pro_star",
        "u.lite",
        "u.google_tv",
        "u.supreme_lock"
      )
      .where("u.id", userId)
      .first();

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    /*
    |--------------------------------------------------------------------------
    | GET PARENT CHAIN
    |--------------------------------------------------------------------------
    */

    const parentChain = [];

    let currentParentId = user.parent_id;
    let level = 0;

    const MAX_LEVEL = 20;

    while (
      currentParentId !== null &&
      currentParentId !== undefined &&
      Number(currentParentId) > 0 &&
      level < MAX_LEVEL
    ) {
      const parent = await db("users")
        .select(
          "id",
          "organization_name",
          "role_id",
          "name",
          "email",
          "phone",
          "parent_id",
          "company_address",
          "country",
          "state",
          "city"
        )
        .where("id", Number(currentParentId))
        .first();

      if (!parent) {
        break;
      }

      parentChain.push(parent);

      currentParentId = parent.parent_id;
      level++;
    }

    /*
    |--------------------------------------------------------------------------
    | REVERSE PARENT CHAIN
    |--------------------------------------------------------------------------
    */

    parentChain.reverse();

    /*
    |--------------------------------------------------------------------------
    | RESPONSE
    |--------------------------------------------------------------------------
    */

    return res.status(200).json({
      success: true,
      message: "Staff data fetched successfully",
      data: {
        ...user,

        direct_parent:
          parentChain.length > 0
            ? parentChain[parentChain.length - 1]
            : null,

        parent_chain: parentChain,
      },
    });
  } catch (error) {
    console.error("GET STAFF DATA ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to get staff data",
      error: error.message,
    });
  }
};

//Interal login
export const loginAsUser = async (req, res) => {
  try {
    const loggedInUser = req.user;
    const { user_id } = req.body;

    if (!user_id) {
      return res.status(400).json({
        success: false,
        message: "User ID is required",
      });
    }

    const targetUser = await db("users as u")
      .leftJoin(
        "role_permission as rp",
        "u.role_permission_id",
        "rp.id"
      )
      .select(
        "u.id",
        "u.name",
        "u.email",
        "u.role_id",
        "u.parent_id",
        "u.role_permission_id",
        "rp.permission"
      )
      .where("u.id", user_id)
      .first();

    if (!targetUser) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    const isCurrentlyImpersonating =
      loggedInUser.is_impersonating === true ||
      loggedInUser.is_impersonating === 1 ||
      loggedInUser.is_impersonating === "true";

    const originalRoleId =
      isCurrentlyImpersonating &&
      loggedInUser.original_role_id !== null &&
      loggedInUser.original_role_id !== undefined
        ? Number(loggedInUser.original_role_id)
        : Number(loggedInUser.role_id);

    const originalUserId =
      isCurrentlyImpersonating &&
      loggedInUser.original_user_id !== null &&
      loggedInUser.original_user_id !== undefined
        ? Number(loggedInUser.original_user_id)
        : Number(loggedInUser.id);

    const targetRoleId = Number(targetUser.role_id);

    const isOriginalUser =
      Number(targetUser.id) === Number(originalUserId);

    const isSameCurrentUser =
      Number(targetUser.id) === Number(loggedInUser.id);

    if (
      !isOriginalUser &&
      !isSameCurrentUser &&
      targetRoleId <= originalRoleId
    ) {
      return res.status(403).json({
        success: false,
        message: "You can only login as a lower level user",
      });
    }

    let permission = targetUser.permission;

    if (typeof permission === "string") {
      try {
        permission = JSON.parse(permission);
      } catch {
        permission = {};
      }
    }

    if (!permission || typeof permission !== "object") {
      permission = {};
    }

    const token = jwt.sign(
      {
        id: targetUser.id,
        role_id: targetRoleId,
        email: targetUser.email,
        original_user_id: originalUserId,
        original_role_id: originalRoleId,
        is_impersonating: true,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "7d",
      }
    );

    return res.status(200).json({
      success: true,
      message: "Login as user successful",
      token,
      user: {
        id: targetUser.id,
        name: targetUser.name,
        email: targetUser.email,
        role_id: targetRoleId,
        parent_id: targetUser.parent_id || null,
        role_permission_id: targetUser.role_permission_id || null,
        role_permission: {
          permission,
        },
      },
    });
  } catch (error) {
    console.error("Login As User Error:", error);

    return res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};


export const getModules = async (req, res) => {
    try {
        const { search, status } = req.query;

        let query = db("modules").select(
            "id",
            "name",
            "slug",
            "icon",
            "sequence",
            "status",
            "created_at",
            "updated_at"
        );

        if (search) {
            query = query.where(function () {
                this.where("name", "like", `%${search}%`)
                    .orWhere("slug", "like", `%${search}%`);
            });
        }

        if (status !== undefined && status !== "") {
            query = query.where("status", status);
        }

        const rows = await query
            .orderBy("sequence", "asc")
            .orderBy("id", "asc");

        return res.status(200).json({
            success: true,
            count: rows.length,
            data: rows
        });
    } catch (error) {
        console.error("Get Modules Error:", error);

        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
};


export const updateModule = async (req, res) => {
    try {
        const { id } = req.params;
        const { status, action } = req.body;

        if (!id) {
            return res.status(400).json({
                success: false,
                message: "Module ID is required"
            });
        }

        const existing = await db("modules")
            .select("id")
            .where("id", id)
            .first();

        if (!existing) {
            return res.status(404).json({
                success: false,
                message: "Module not found"
            });
        }

        // DELETE MODULE
        if (action === "delete") {
            await db("modules")
                .where("id", id)
                .del();

            return res.status(200).json({
                success: true,
                message: "Module deleted successfully"
            });
        }

        // UPDATE STATUS
        if (status === undefined || status === null) {
            return res.status(400).json({
                success: false,
                message: "Status is required"
            });
        }

        await db("modules")
            .where("id", id)
            .update({
                status: Number(status)
            });

        const updatedModule = await db("modules")
            .where("id", id)
            .first();

        return res.status(200).json({
            success: true,
            message: "Module status updated successfully",
            data: updatedModule
        });

    } catch (error) {
        console.error("UPDATE MODULE ERROR:", error);

        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
};

// UPADTE USER ACTIVE / INACTIVE
export const updateUserStatus = async (req, res) => {
  try {
    const { user_id, userStatus } = req.body;

    if (!user_id) {
      return res.status(400).json({
        success: false,
        message: "User ID is required",
      });
    }

    const status = Number(userStatus);

    if (status !== 0 && status !== 1) {
      return res.status(400).json({
        success: false,
        message: "userStatus must be 0 (Inactive) or 1 (Active)",
      });
    }

    const user = await db("users")
      .select("id", "name", "userStatus")
      .where("id", user_id)
      .first();

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    await db("users")
      .where("id", user_id)
      .update({
        userStatus: status,
      });

    const statusText = status === 1 ? "Active" : "Inactive";

    return res.status(200).json({
      success: true,
      message: `User status updated to ${statusText}`,
      user: {
        id: user.id,
        name: user.name,
        userStatus: status,
        status: statusText,
      },
    });
  } catch (error) {
    console.error("UPDATE USER STATUS ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to update user status",
      error: error.message,
    });
  }
};

//add submodule
export const createSubModule = async (req, res) => {
    try {
        const { module_id, name, icon, status } = req.body;

        if (!module_id || !name) {
            return res.status(400).json({
                success: false,
                message: "Module ID and name are required"
            });
        }

        const parentModule = await db("modules")
            .select("id")
            .where("id", module_id)
            .first();

        if (!parentModule) {
            return res.status(404).json({
                success: false,
                message: "Parent module not found"
            });
        }

        const existingSubModule = await db("sub_modules")
            .select("id")
            .where("module_id", module_id)
            .where("name", name)
            .first();

        if (existingSubModule) {
            return res.status(409).json({
                success: false,
                message: "Sub module already exists under this module"
            });
        }

        const [id] = await db("sub_modules").insert({
            module_id: Number(module_id),
            name: name.trim(),
            icon: icon || null,
            status: status ?? 1
        });

        const subModule = await db("sub_modules")
            .where("id", id)
            .first();

        return res.status(201).json({
            success: true,
            message: "Sub module created successfully",
            data: subModule
        });
    } catch (error) {
        console.error("CREATE SUB MODULE ERROR:", error);

        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
};

// get submodule
export const getAllSubModules = async (req, res) => {
    try {
        const subModules = await db("sub_modules")
            .select(
                "id",
                "name",
                "icon",
                "status",
                "created_at",
                "updated_at"
            )
            .orderBy("id", "asc");

        return res.status(200).json({
            success: true,
            data: subModules
        });
    } catch (error) {
        console.error("GET ALL SUB MODULES ERROR:", error);

        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
};

//delete submodule
export const deleteSubModule = async (req, res) => {
    try {
        const { id } = req.params;

        if (!id) {
            return res.status(400).json({
                success: false,
                message: "Sub module ID is required"
            });
        }

        const subModule = await db("sub_modules")
            .where("id", id)
            .first();

        if (!subModule) {
            return res.status(404).json({
                success: false,
                message: "Sub module not found"
            });
        }

        await db("sub_modules")
            .where("id", id)
            .del();

        return res.status(200).json({
            success: true,
            message: "Sub module deleted successfully",
            data: subModule
        });
    } catch (error) {
        console.error("DELETE SUB MODULE ERROR:", error);

        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
};

//edit submoule
export const updateSubModule = async (req, res) => {
    try {
        const { id } = req.params;
        const { status } = req.body;

        if (!id) {
            return res.status(400).json({
                success: false,
                message: "Sub module ID is required"
            });
        }

        if (status === undefined || status === null) {
            return res.status(400).json({
                success: false,
                message: "Status is required"
            });
        }

        const subModule = await db("sub_modules")
            .where("id", id)
            .first();

        if (!subModule) {
            return res.status(404).json({
                success: false,
                message: "Sub module not found"
            });
        }

        await db("sub_modules")
            .where("id", id)
            .update({
                status: Number(status)
            });

        const updatedSubModule = await db("sub_modules")
            .where("id", id)
            .first();

        return res.status(200).json({
            success: true,
            message: "Sub module status updated successfully",
            data: updatedSubModule
        });
    } catch (error) {
        console.error("UPDATE SUB MODULE STATUS ERROR:", error);

        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
};

//get role
export const getRoles = async (req, res) => {
    try {
        const roles = await db("roles")
            .select(
                "id",
                "role_id",
                "name",
                "slug",
                "icon",
                "sequence",
                "status",
                "created_at",
                "updated_at"
            )
            .orderBy("sequence", "asc");

        return res.status(200).json({
            success: true,
            count: roles.length,
            data: roles,
        });
    } catch (error) {
        console.error("GET ROLES ERROR:", error);

        return res.status(500).json({
            success: false,
            message: "Internal server error",
        });
    }
};


//GET 
export const getProfiles = async (req, res) => {
  try {
    const createdBy = req.user?.id;

    if (!createdBy) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized",
      });
    }

    const profiles = await db("profile")
      .select(
        "id",
        "created_by",
        "name",
        "status",
        "created_at",
        "updated_at"
      )
      .where("created_by", createdBy)
      .orderBy("id", "desc");

    return res.status(200).json({
      success: true,
      message: "Profiles fetched successfully",
      data: profiles,
    });
  } catch (error) {
    console.error("GET PROFILES DB ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to fetch profiles",
      error: error.message,
    });
  }
};

//post api for profile data
export const createProfile = async (req, res) => {
  try {
    const { name, status = 1 } = req.body;

    const profileName = String(name || "").trim();
    const profileStatus = Number(status);
    const createdBy = req.user?.id;

    if (!createdBy) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized",
      });
    }

    if (!profileName) {
      return res.status(400).json({
        success: false,
        message: "Profile name is required",
      });
    }

    if (![0, 1].includes(profileStatus)) {
      return res.status(400).json({
        success: false,
        message: "Status must be 0 or 1",
      });
    }

    const existingProfile = await db("profile")
      .where("created_by", createdBy)
      .whereRaw("LOWER(`name`) = LOWER(?)", [profileName])
      .first();

    if (existingProfile) {
      return res.status(409).json({
        success: false,
        message: "Profile already exists",
      });
    }

    const [profileId] = await db("profile").insert({
      created_by: createdBy,
      name: profileName,
      status: profileStatus,
      created_at: db.fn.now(),
      updated_at: db.fn.now(),
    });

    const profile = await db("profile")
      .select(
        "id",
        "created_by",
        "name",
        "status",
        "created_at",
        "updated_at"
      )
      .where("id", profileId)
      .where("created_by", createdBy)
      .first();

    return res.status(201).json({
      success: true,
      message: "Profile created successfully",
      data: profile,
    });
  } catch (error) {
    console.error("CREATE PROFILE DB ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to create profile",
      error: error.message,
    });
  }
};

//update/edit  api for profile data
export const updateProfile = async (req, res) => {
  try {
    const { id } = req.params;
    const { name, status } = req.body;
    const createdBy = req.user?.id;

    if (!createdBy) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized",
      });
    }

    const profileName = String(name || "").trim();
    const profileStatus = Number(status);

    if (!profileName) {
      return res.status(400).json({
        success: false,
        message: "Profile name is required",
      });
    }

    if (![0, 1].includes(profileStatus)) {
      return res.status(400).json({
        success: false,
        message: "Status must be 0 or 1",
      });
    }

    const existingProfile = await db("profile")
      .where("id", id)
      .where("created_by", createdBy)
      .first();

    if (!existingProfile) {
      return res.status(404).json({
        success: false,
        message: "Profile not found",
      });
    }

    const duplicateProfile = await db("profile")
      .where("created_by", createdBy)
      .whereRaw("LOWER(`name`) = LOWER(?)", [profileName])
      .whereNot("id", id)
      .first();

    if (duplicateProfile) {
      return res.status(409).json({
        success: false,
        message: "Profile already exists",
      });
    }

    await db("profile")
      .where("id", id)
      .where("created_by", createdBy)
      .update({
        name: profileName,
        status: profileStatus,
        updated_at: db.fn.now(),
      });

    const profile = await db("profile")
      .select(
        "id",
        "created_by",
        "name",
        "status",
        "created_at",
        "updated_at"
      )
      .where("id", id)
      .where("created_by", createdBy)
      .first();

    return res.status(200).json({
      success: true,
      message: "Profile updated successfully",
      data: profile,
    });
  } catch (error) {
    console.error("UPDATE PROFILE DB ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to update profile",
      error: error.message,
    });
  }
};


//role-permission
export const saveRolePermissions = async (req, res) => {
  try {
    const { profile_id, permission } = req.body;

    if (!profile_id || Number(profile_id) <= 0) {
      return res.status(400).json({
        success: false,
        message: "Valid profile_id is required",
      });
    }

    if (
      !permission ||
      typeof permission !== "object" ||
      Array.isArray(permission)
    ) {
      return res.status(400).json({
        success: false,
        message: "Valid permission object is required",
      });
    }

    const profileId = Number(profile_id);

    const profile = await db("profile")
      .where("id", profileId)
      .first();

    if (!profile) {
      return res.status(404).json({
        success: false,
        message: "Profile not found",
      });
    }

    // Only active permissions (value = 1)
    const activePermissions = Object.fromEntries(
      Object.entries(permission).filter(
        ([, value]) => Number(value) === 1
      )
    );

    // Existing profile permission
    const existing = await db("role_permission")
      .where("profile_id", profileId)
      .first();

    // Update
    if (existing) {
      await db("role_permission")
        .where("id", existing.id)
        .update({
          permission: JSON.stringify(activePermissions),
          updated_at: db.fn.now(),
        });

      const updatedData = await db("role_permission")
        .where("id", existing.id)
        .first();

      return res.status(200).json({
        success: true,
        message: "Role permissions updated successfully",
        data: {
          id: updatedData.id,
          profile_id: updatedData.profile_id,
          permission:
            typeof updatedData.permission === "string"
              ? JSON.parse(updatedData.permission)
              : updatedData.permission,
          created_at: updatedData.created_at,
          updated_at: updatedData.updated_at,
        },
      });
    }

    // Create
    const [insertedId] = await db("role_permission")
      .insert({
        profile_id: profileId,
        permission: JSON.stringify(activePermissions),
      });

    const createdData = await db("role_permission")
      .where("id", insertedId)
      .first();

    return res.status(201).json({
      success: true,
      message: "Role permissions created successfully",
      data: {
        id: createdData.id,
        profile_id: createdData.profile_id,
        permission:
          typeof createdData.permission === "string"
            ? JSON.parse(createdData.permission)
            : createdData.permission,
        created_at: createdData.created_at,
        updated_at: createdData.updated_at,
      },
    });
  } catch (error) {
    console.error("SAVE ROLE PERMISSIONS ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to save role permissions",
      error: error.message,
    });
  }
};

//get permission
export const getRolePermissions = async (req, res) => {
  try {

    const profileId = Number(req.params.profile_id);

    const data = await db("role_permission")
      .where("profile_id", profileId)
      .first();

    return res.status(200).json({
      success: true,
      data: data || null,
    });
  } catch (error) {
    console.error("ROLE PERMISSION ERROR:");
    console.error(error);

    return res.status(500).json({
      success: false,
      message: error.message,
      code: error.code || null,
    });
  }
};

//country get api
export const getCountries = async (req, res) => {
    try {
        const countries = await db("loksiz_master_countries_migrated")
            .select(
                "country_id",
                "country_name",
                "currency",
                "country_code",
                "iso3",
                "numeric_code",
                "mobile_code",
                "capital",
                "currency_name",
                "currency_symbol",
                "tld",
                "native",
                "region",
                "region_id",
                "subregion",
                "subregion_id",
                "nationality",
                "timezones",
                "translations",
                "latitude",
                "longitude",
                "emoji",
                "emojiU",
                "flag",
                "wikiDataId",
                "is_active",
                "created_at",
                "updated_at"
            )
            .where("is_active", 1)
            .orderBy("country_name", "asc");

        return res.status(200).json({
            success: true,
            message: "Countries fetched successfully",
            data: countries,
        });
    } catch (error) {
        console.error("GET COUNTRIES ERROR:", error);

        return res.status(500).json({
            success: false,
            message: "Failed to fetch countries",
            error: error.message,
        });
    }
};

// get state api accoridng to the country
export const getStates = async (req, res) => {
    try {
        const { country_id } = req.query;

        if (!country_id) {
            return res.status(400).json({
                success: false,
                message: "country_id is required",
            });
        }

        const countryId = Number(country_id);

        if (!Number.isInteger(countryId) || countryId <= 0) {
            return res.status(400).json({
                success: false,
                message: "Invalid country_id",
            });
        }

        const states = await db("loksiz_master_states")
            .select(
                "id",
                "name",
                "country_id",
                "country_code",
                "fips_code",
                "iso2",
                "type",
                "level",
                "parent_id",
                "latitude",
                "longitude",
                "created_at",
                "updated_at",
                "flag",
                "wikiDataId"
            )
            .where("country_id", countryId)
            .orderBy("name", "asc");

        return res.status(200).json({
            success: true,
            message: "States fetched successfully",
            data: states,
        });
    } catch (error) {
        console.error("GET STATES ERROR:", error);

        return res.status(500).json({
            success: false,
            message: "Failed to fetch states",
            error: error.message,
        });
    }
};


//get city api according to the state
export const getCities = async (req, res) => {
    try {
        const { state_id } = req.query;

        if (!state_id) {
            return res.status(400).json({
                success: false,
                message: "state_id is required",
            });
        }

        const stateId = Number(state_id);

        if (!Number.isInteger(stateId) || stateId <= 0) {
            return res.status(400).json({
                success: false,
                message: "Invalid state_id",
            });
        }

        const cities = await db("loksiz_master_cities")
            .select(
                "id",
                "name",
                "state_id",
                "state_code",
                "country_id",
                "country_code",
                "latitude",
                "longitude",
                "created_at",
                "updated_at",
                "flag",
                "wikiDataId"
            )
            .where("state_id", stateId)
            .orderBy("name", "asc");

        return res.status(200).json({
            success: true,
            message: "Cities fetched successfully",
            data: cities,
        });
    } catch (error) {
        console.error("GET CITIES ERROR:", error);

        return res.status(500).json({
            success: false,
            message: "Failed to fetch cities",
            error: error.message,
        });
    }
};

