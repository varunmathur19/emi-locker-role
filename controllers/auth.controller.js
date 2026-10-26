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
import { BOOLEAN } from "../constants/roles.js";
import fs from "fs";
import path from "path";
import { parsePhoneNumberFromString } from "libphonenumber-js";

const isPermissionEnabled = (value) => {
    if (typeof value === "boolean") {
        return value;
    }

    if (typeof value === "number") {
        return value === 1;
    }

    if (typeof value === "string") {
        return (
            value === "1" ||
            value.toLowerCase() === "true"
        );
    }

    if (value && typeof value === "object") {
        if (value.status !== undefined) {
            return Number(value.status) === 1;
        }

        if (value.view !== undefined) {
            return Number(value.view) === 1;
        }

        if (value.access !== undefined) {
            return Number(value.access) === 1;
        }

        return true;
    }

    return false;
};

const getStaffPermissions = async (user) => {
    if (
        Number(user?.role_id) !== ROLES.STAFF ||
        !user?.role_permission_id
    ) {
        return null;
    }

    const rolePermission = await db("role_permission")
        .select("permission")
        .where("id", Number(user.role_permission_id))
        .first();

    if (!rolePermission?.permission) {
        return null;
    }

    try {
        const permission =
            typeof rolePermission.permission === "string"
                ? JSON.parse(rolePermission.permission)
                : rolePermission.permission;

        if (
            !permission ||
            typeof permission !== "object" ||
            Array.isArray(permission)
        ) {
            return null;
        }

        return permission;
    } catch {
        return null;
    }
};

const hasStaffPermission = (
    permissions,
    moduleId,
    subModuleId
) => {
    if (!permissions) {
        return false;
    }

    if (
        moduleId === undefined ||
        moduleId === null ||
        subModuleId === undefined ||
        subModuleId === null
    ) {
        return false;
    }

    const key = `${moduleId}.${subModuleId}`;

    return isPermissionEnabled(
        permissions[key]
    );
};

const hasAnyStaffModulePermission = (
    permissions,
    moduleId
) => {
    if (!permissions) {
        return false;
    }

    if (
        moduleId === undefined ||
        moduleId === null
    ) {
        return false;
    }

    const prefix = `${moduleId}.`;

    return Object.entries(permissions).some(
        ([key, value]) => {
            if (!key.startsWith(prefix)) {
                return false;
            }

            return isPermissionEnabled(value);
        }
    );
};



const getRoleForPermission = (roleId) =>
    db("roles")
        .select(
            "role_id",
            "name",
            "slug"
        )
        .where(
            "role_id",
            Number(roleId)
        )
        .first();

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
            transaction_pin,
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

        if (
            !name ||
            !email ||
            !phone ||
            !password ||
            !confirm_password ||
            !transaction_pin
        ) {
            return res.status(400).json({
                success: false,
                message:
                    "Name, email, phone, password, confirm password and transaction PIN are required",
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
                message: "Password must start with a capital letter",
            });
        }

        const normalizedTransactionPin = String(
            transaction_pin
        ).trim();

        if (!/^\d{4}$/.test(normalizedTransactionPin)) {
            return res.status(400).json({
                success: false,
                message: "Transaction PIN must be exactly 4 digits",
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

        if (requestedRoleId === 9) {
            if (
                profile_id === undefined ||
                profile_id === null ||
                profile_id === ""
            ) {
                return res.status(400).json({
                    success: false,
                    message: "Assigned role is required for Staff",
                });
            }
        }

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

        if (
            creatorRole !== ROLES.STAFF &&
            creatorRole !== 8 &&
            requestedRoleId !== 9 &&
            requestedRoleId <= creatorRole
        ) {
            return res.status(403).json({
                success: false,
                message: "You are not allowed to create this role",
            });
        }

        if (creatorRole === 8) {
            return res.status(403).json({
                success: false,
                message: "Employee cannot create users",
            });
        }

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

        let finalParentId = null;

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
            const normalizedCountryName = selectedCountry
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
        } catch {
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
                    message: "Invalid assigned role",
                });
            }

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

            if (
                role_permission !== undefined &&
                role_permission !== null &&
                role_permission !== ""
            ) {
                if (typeof role_permission === "string") {
                    try {
                        permissionData =
                            JSON.parse(role_permission);
                    } catch {
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

            const existingRolePermission =
                await db("role_permission")
                    .where(
                        "profile_id",
                        selectedProfileId
                    )
                    .first();

            if (existingRolePermission) {
                rolePermissionId =
                    existingRolePermission.id;

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
                const [newRolePermissionId] =
                    await db("role_permission")
                        .insert({
                            profile_id:
                                selectedProfileId,
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

        const hashedPassword =
            await bcrypt.hash(password, 10);

        const finalOrganizationName =
            requestedRoleId === 9
                ? creator.organization_name || null
                : organization_name
                ? String(organization_name).trim()
                : null;

        const userData = {
            organization_name:
                finalOrganizationName,
            role_id: requestedRoleId,
            role_permission_id:
                requestedRoleId === 9
                    ? rolePermissionId
                    : null,
            parent_id: finalParentId,
            name: String(name).trim(),
            email: normalizedEmail,
            phone: normalizedPhone,
            password: hashedPassword,
            transaction_pin: normalizedTransactionPin,
            company_address: company_address
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

        const userId =
            await createUserModel(userData);

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
                transaction_pin:
                    normalizedTransactionPin,
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

    const user = await findUserByEmail(
      String(email).trim().toLowerCase()
    );

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    if (Number(user.userStatus) === 0) {
      return res.status(403).json({
        success: false,
        message: "Your account is inactive",
      });
    }

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

    let staffPermission = null;

    const roleId = Number(user.role_id);
    const isStaff = roleId === 9;

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
        let permission = rolePermission.permission;

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

      role_permission_id: isStaff
        ? user.role_permission_id
        : null,

      staff_permission: isStaff
        ? staffPermission
        : null,
    };

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
    // 1. Pagination
    const page = Math.max(Number(req.query.page) || 1, 1);
    const limit = Math.max(Number(req.query.limit) || 10, 1);
    const offset = (page - 1) * limit;

    // 2. Validate logged-in user
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
        message: "Invalid logged-in user role",
      });
    }

    // 3. Role configuration
    const MASTER_ADMIN_ROLE_ID = 0;
    const ADMIN_ROLE_ID = 1;
    const STAFF_ROLE_ID = 9;

    const isMasterAdmin =
      loggedInRoleId === MASTER_ADMIN_ROLE_ID;

    const isAdmin =
      loggedInRoleId === ADMIN_ROLE_ID;

    const isStaff =
      loggedInRoleId === STAFF_ROLE_ID;

    const NEXT_ROLE_BY_ROLE = {
      0: 1,
      1: 2,
      2: 3,
      3: 4,
      4: 5,
      5: 6,
      6: 7,
      7: 8,
      8: 9,
    };

    // 4. Read query parameters
    const readQueryValue = (key) => {
      const value = req.query[key];

      if (
        value === undefined ||
        value === null ||
        String(value).trim() === ""
      ) {
        return null;
      }

      return String(value).trim();
    };

    let role_id = null;

    const roleValue = readQueryValue("role_id");

    if (roleValue !== null) {
      role_id = Number(roleValue);

      if (!Number.isInteger(role_id) || role_id < 0) {
        return res.status(400).json({
          success: false,
          message: "Invalid role_id",
        });
      }
    }

    const search = readQueryValue("search");
    const country = readQueryValue("country");
    const state = readQueryValue("state");
    const city = readQueryValue("city");

    // 5. Status filter
    let status = null;

    const statusValue = readQueryValue("status");

    if (statusValue !== null) {
      const normalizedStatus = statusValue.toLowerCase();

      if (["active", "1"].includes(normalizedStatus)) {
        status = 1;
      } else if (
        ["inactive", "0"].includes(normalizedStatus)
      ) {
        status = 0;
      } else {
        return res.status(400).json({
          success: false,
          message: "Invalid status",
        });
      }
    }

    // 6. Staff hierarchy validation
    let staffCreatorId = null;
    let staffCreatorRoleId = null;
    let transferTargetRoleId = null;

    // Keep this false unless getAllUsers explicitly requires
    // a separate, validated transfer-access flag.
    let staffRoleAccess = false;

    if (isStaff) {
      const staffUser = await db("users")
        .select(
          "id",
          "role_id",
          "role_permission_id",
          "created_by",
          "parent_id"
        )
        .where("id", loggedInUserId)
        .first();

      if (!staffUser) {
        return res.status(404).json({
          success: false,
          message: "Logged-in staff user not found",
        });
      }

      // Resolve the Staff creator.
      const creatorValue =
        staffUser.created_by ?? staffUser.parent_id;

      staffCreatorId = Number(creatorValue);

      if (
        !Number.isInteger(staffCreatorId) ||
        staffCreatorId <= 0 ||
        staffCreatorId === loggedInUserId
      ) {
        return res.status(403).json({
          success: false,
          message: "Staff creator not found",
        });
      }

      const creator = await db("users")
        .select("id", "role_id")
        .where("id", staffCreatorId)
        .first();

      if (!creator) {
        return res.status(403).json({
          success: false,
          message: "Staff creator not found",
        });
      }

      staffCreatorRoleId = Number(creator.role_id);

      // Determine the next role in the hierarchy.
      transferTargetRoleId =
        NEXT_ROLE_BY_ROLE[staffCreatorRoleId] ?? null;

      if (transferTargetRoleId === null) {
        return res.status(403).json({
          success: false,
          message:
            "No transfer target role is configured for this Staff creator",
        });
      }

      // Validate an explicitly requested role.
      if (role_id !== null) {
        const requestedRole = await getRoleForPermission(role_id);

        if (!requestedRole) {
          return res.status(400).json({
            success: false,
            message: "Requested role not found",
          });
        }
      }

      // IMPORTANT:
      // Do not check Transfer Points permission here.
      // This endpoint lists users and is also used for dashboard counts.
      // Transfer-specific permissions should be validated by the
      // actual Transfer/Revert/Schema Transfer endpoints.

      console.log("STAFF CREATOR DETAILS:", {
        staffId: loggedInUserId,
        creatorId: staffCreatorId,
        creatorRoleId: staffCreatorRoleId,
        transferTargetRoleId,
      });
    }

    // 7. Determine access scope
    const canSeeAllUsers =
      isMasterAdmin ||
      isAdmin ||
      (
        isStaff &&
        [
          MASTER_ADMIN_ROLE_ID,
          ADMIN_ROLE_ID,
        ].includes(staffCreatorRoleId)
      );

    // 8. Fetch users
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
      staffRoleAccess,
      staffCreatorId,
      canSeeAllUsers,
      transferTargetRoleId
    );

    // 9. Normalize result
    const resultUsers = Array.isArray(result?.users)
      ? result.users
      : [];

    const users = await Promise.all(
      resultUsers.map(async (user) => {
        let parsedPermission = {};

        if (user.role_permission) {
          try {
            parsedPermission =
              typeof user.role_permission === "string"
                ? JSON.parse(user.role_permission)
                : user.role_permission;

            if (
              !parsedPermission ||
              typeof parsedPermission !== "object" ||
              Array.isArray(parsedPermission)
            ) {
              parsedPermission = {};
            }
          } catch {
            parsedPermission = {};
          }
        }

        let wallet_balance = user.wallet_balance ?? [];

        if (typeof wallet_balance === "string") {
          try {
            wallet_balance = JSON.parse(wallet_balance);
          } catch {
            wallet_balance = [];
          }
        }

        if (!Array.isArray(wallet_balance)) {
          wallet_balance = [];
        }

        let parent_name = user.parent_name || null;

        let parent_organization_name =
          user.parent_organization_name || null;

        // Preserve CNF parent information.
        if (
          Number(user.role_id) === 2 &&
          user.parent_id
        ) {
          const parentUser = await db("users")
            .select("name", "organization_name")
            .where("id", Number(user.parent_id))
            .first()
            .catch((error) => {
              console.error("CNF PARENT FETCH ERROR:", error);
              return null;
            });

          if (parentUser) {
            parent_name = parentUser.name || null;

            parent_organization_name =
              parentUser.organization_name || null;
          }
        }

        return {
          ...user,
          wallet_balance,
          parent_name,
          parent_organization_name,
          role_permission: {
            id: user.role_permission_id || null,
            profile_id: user.profile_id || null,
            profile_name: user.profile_name || null,
            permission: parsedPermission,
          },
        };
      })
    );

    // 10. Pagination and debug logs
    const totalUsers = Math.max(
      Number(result?.total) || 0,
      0
    );

    // console.log("GET USERS RESULT:", {
    //   userId: loggedInUserId,
    //   roleId: loggedInRoleId,
    //   isStaff,
    //   staffCreatorId,
    //   staffCreatorRoleId,
    //   canSeeAllUsers,
    //   requestedRoleId: role_id,
    //   transferTargetRoleId,
    //   returnedUsers: users.length,
    //   totalUsers,
    //   page,
    //   limit,
    //   offset,
    // });

    // 11. API response
    return res.status(200).json({
      success: true,
      pagination: {
        currentPage: page,
        totalPages: Math.ceil(totalUsers / limit),
        limit,
        totalUsers,
      },
      data: users,
      ...(isStaff ? { transferTargetRoleId } : {}),
    });
  } catch (error) {
    console.error("GET USERS ERROR:", error);

    return res.status(500).json({
      success: false,
      message: error?.message || "Failed to get users",
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
        "u.wallet_balance",
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
            country_code,
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

        let normalizedPhone = undefined;

        if (phone !== undefined) {
            const rawPhone = String(phone || "").trim();
            const selectedCountryCode = String(
                country_code || ""
            )
                .trim()
                .toUpperCase();

            const parsedPhone = rawPhone.startsWith("+")
                ? parsePhoneNumberFromString(rawPhone)
                : parsePhoneNumberFromString(
                    rawPhone,
                    selectedCountryCode || undefined
                );

            if (!parsedPhone?.isValid()) {
                return res.status(400).json({
                    success: false,
                    message: "Invalid phone number for selected country",
                });
            }

            if (
                selectedCountryCode &&
                parsedPhone.country !== selectedCountryCode
            ) {
                return res.status(400).json({
                    success: false,
                    message: "Phone number does not match selected country",
                });
            }

            normalizedPhone = parsedPhone.number;

            const existingPhone = await db("users")
                .select("id")
                .where("phone", normalizedPhone)
                .whereNot("id", userId)
                .first();

            if (existingPhone) {
                return res.status(409).json({
                    success: false,
                    message: "Phone number already exists",
                });
            }
        }

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

        const result = await db.transaction(
            async (trx) => {
               
                let rolePermissionId =
                    existingUser.role_permission_id ??
                    null;

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


                    if (profilePermission) {
                        rolePermissionId =
                            profilePermission.id;

                    
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

             
                if (name !== undefined) {
                    updateData.name = name;
                }

                if (email !== undefined) {
                    updateData.email = email;
                }

                if (phone !== undefined) {
                    updateData.phone = normalizedPhone;
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

               
                if (
                    parent_id !== undefined
                ) {
                    updateData.parent_id =
                        normalizedParentId;
                }

             
                if (
                    rolePermissionId !== null
                ) {
                    updateData.role_permission_id =
                        rolePermissionId;
                }

               
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

              
                if (
                    password !== undefined &&
                    password !== null &&
                    password !== ""
                ) {
                    updateData.password =
                        password;
                }

             

                updateData.updated_at =
                    trx.fn.now();

              

                await trx("users")
                    .where("id", userId)
                    .update(updateData);



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

             
                return {
                    ...updatedUser,

                    role_permission:
                        finalRolePermission,
                };
            }
        );

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
        "u.role_permission_id",

        "p.id as profile_id",
        "p.name as profile_name",
        "p.status as profile_status",

        "u.name",
        "u.email",
        "u.phone",
        "u.transaction_pin",
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

    parentChain.reverse();

    return res.status(200).json({
      success: true,
      message: "Staff data fetched successfully",
      data: {
        ...user,
        transaction_pin: user.transaction_pin || "",
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

    const targetUser = await db("users as u")
      .select(
        "u.id",
        "u.name",
        "u.email",
        "u.role_id",
        "u.parent_id",
        "u.userStatus",
        "u.role_permission_id"
      )
      .where("u.id", user_id)
      .first();

    if (!targetUser) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    const targetRoleId = Number(targetUser.role_id);

    const isMasterAdmin = originalRoleId === 0;

    const isOriginalUser =
      Number(targetUser.id) === originalUserId;

    const isSameCurrentUser =
      Number(targetUser.id) === Number(loggedInUser.id);

    if (
      !isMasterAdmin &&
      !isOriginalUser &&
      !isSameCurrentUser &&
      targetRoleId <= originalRoleId
    ) {
      return res.status(403).json({
        success: false,
        message: "You can only login as a lower level user",
      });
    }

    let staffPermission = null;

    const isStaff = targetRoleId === 9;

    if (isStaff && targetUser.role_permission_id) {
      const rolePermission = await db("role_permission")
        .select(
          "id",
          "profile_id",
          "permission"
        )
        .where(
          "id",
          Number(targetUser.role_permission_id)
        )
        .first();

      if (rolePermission) {
        let permission = rolePermission.permission;

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

    const userResponse = {
      id: targetUser.id,
      name: targetUser.name,
      email: targetUser.email,
      role_id: targetRoleId,
      userStatus: Number(targetUser.userStatus),
      parent_id: targetUser.parent_id,
      role_permission_id: isStaff
        ? targetUser.role_permission_id
        : null,
      staff_permission: isStaff
        ? staffPermission
        : null,
    };

    return res.status(200).json({
      success: true,
      message: "Login as user successful",
      token,
      user: userResponse,
    });
  } catch (error) {
    console.error("Login As User Error:", error);

    return res.status(500).json({
      success: false,
      message:
        error.message ||
        "Internal server error",
    });
  }
};
export const getModules = async (req, res) => {
    try {
        const { search, status } = req.query;

        let query = db("modules").select(
            "id",
            "role_id",
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
            data: subModules,
        });
    } catch (error) {
        console.error("GET ALL SUB MODULES ERROR:", error);

        return res.status(500).json({
            success: false,
            message: "Internal server error",
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

// update status active /inactive

export const updateRoleStatus = async (req, res) => {
    try {
        const { id } = req.params;
        const { status } = req.body;

        if (!id) {
            return res.status(400).json({
                success: false,
                message: "Role ID is required",
            });
        }

        if (![0, 1].includes(Number(status))) {
            return res.status(400).json({
                success: false,
                message: "Status must be 0 or 1",
            });
        }

        const role = await db("roles")
            .where("id", id)
            .first();

        if (!role) {
            return res.status(404).json({
                success: false,
                message: "Role not found",
            });
        }

        await db("roles")
            .where("id", id)
            .update({
                status: Number(status),
                updated_at: db.fn.now(),
            });

        return res.status(200).json({
            success: true,
            message: "Role status updated successfully",
        });
    } catch (error) {
        console.error("UPDATE ROLE STATUS ERROR:", error);

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

    // Check existing profile
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

    const updateData = {};

    // =========================
    // Update Name
    // =========================
    if (name !== undefined) {
      const profileName = String(name).trim();

      if (!profileName) {
        return res.status(400).json({
          success: false,
          message: "Profile name is required",
        });
      }

      // Check duplicate name
      const duplicateProfile = await db("profile")
        .where("created_by", createdBy)
        .whereRaw(
          "LOWER(`name`) = LOWER(?)",
          [profileName]
        )
        .whereNot("id", id)
        .first();

      if (duplicateProfile) {
        return res.status(409).json({
          success: false,
          message: "Profile already exists",
        });
      }

      updateData.name = profileName;
    }

    // =========================
    // Update Status
    // =========================
    if (status !== undefined) {
      const profileStatus = Number(status);

      if (![0, 1].includes(profileStatus)) {
        return res.status(400).json({
          success: false,
          message: "Status must be 0 or 1",
        });
      }

      updateData.status = profileStatus;
    }

    // Nothing to update
    if (Object.keys(updateData).length === 0) {
      return res.status(400).json({
        success: false,
        message: "Nothing to update",
      });
    }

    // Always update timestamp
    updateData.updated_at = db.fn.now();

    await db("profile")
      .where("id", id)
      .where("created_by", createdBy)
      .update(updateData);

    // Get updated profile
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
    console.error(
      "UPDATE PROFILE DB ERROR:",
      error
    );

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
    console.error("ROLE PERMISSION ERROR:", error);

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

//get key-setting data




export const getKeySettings = async (req, res) => {
  try {
    const loggedInUserId = Number(req.user?.id);

    // 1. Validate logged-in user
    if (!Number.isInteger(loggedInUserId) || loggedInUserId <= 0) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized user",
      });
    }

    // 2. Fetch logged-in user
    const loggedInUser = await db("users")
      .select("id", "role_id", "parent_id", "created_by")
      .where("id", loggedInUserId)
      .first();

    if (!loggedInUser) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // 3. Determine wallet owner
    let walletUserId = Number(loggedInUser.id);

    if (Number(loggedInUser.role_id) === 9) {
      walletUserId = Number(
        loggedInUser.created_by || loggedInUser.parent_id
      );
    }

    if (!Number.isInteger(walletUserId) || walletUserId <= 0) {
      return res.status(400).json({
        success: false,
        message: "Staff parent or creator user not found",
      });
    }

    // 4. Fetch wallet balance
    const walletUser = await db("users")
      .select("id", "wallet_balance")
      .where("id", walletUserId)
      .first();

    if (!walletUser) {
      return res.status(404).json({
        success: false,
        message: "Wallet owner not found",
      });
    }

    // 5. Parse wallet_balance safely
    let walletBalance = walletUser.wallet_balance ?? [];

    if (Buffer.isBuffer(walletBalance)) {
      walletBalance = walletBalance.toString("utf8");
    }

    for (let i = 0; i < 3 && typeof walletBalance === "string"; i++) {
      if (!walletBalance.trim()) {
        walletBalance = [];
        break;
      }

      try {
        walletBalance = JSON.parse(walletBalance);
      } catch (error) {
        console.error("WALLET BALANCE JSON ERROR:", error);

        return res.status(500).json({
          success: false,
          message: "Invalid wallet balance JSON format",
        });
      }
    }

    // 6. Handle object formats
    if (
      walletBalance &&
      typeof walletBalance === "object" &&
      !Array.isArray(walletBalance)
    ) {
      if (
        walletBalance.name !== undefined ||
        walletBalance.available !== undefined ||
        walletBalance.balance !== undefined
      ) {
        walletBalance = [walletBalance];
      } else {
        walletBalance = Object.entries(walletBalance).map(
          ([name, value]) => {
            if (
              value &&
              typeof value === "object" &&
              !Array.isArray(value)
            ) {
              return {
                ...value,
                name: value.name ?? name,
              };
            }

            const available = Number(value) || 0;

            return {
              name,
              balance: available,
              consumed: 0,
              available,
            };
          }
        );
      }
    }

    if (!Array.isArray(walletBalance)) {
      walletBalance = [];
    }

    // Remove the known legacy placeholder
    walletBalance = walletBalance.filter(
      (item) =>
        !(
          item?._legacy_single_balance === true &&
          (item?.name === null || item?.name === undefined)
        )
    );

    // 7. Fetch key settings
    const keySettings = await db("key_setting")
      .select("*")
      .orderBy("id", "asc");

    // 8. Match wallet entries with key settings
    const normalize = (value) =>
      String(value ?? "").trim().toLowerCase();

    const data = keySettings.map((key) => {
      const walletItem = walletBalance.find((item) => {
        const itemKeyId = Number(
          item?.key_setting_id ??
            item?.keySettingId ??
            item?.key_id ??
            item?.keyId
        );

        // Prefer matching by key ID when available.
        if (Number.isInteger(itemKeyId) && itemKeyId > 0) {
          return itemKeyId === Number(key.id);
        }

        // Support older wallet entries that only have a name.
        return normalize(item?.name) === normalize(key.name);
      });

      const consumed = Number(walletItem?.consumed ?? 0);

      const balance =
        walletItem?.balance !== undefined &&
        walletItem?.balance !== null
          ? Number(walletItem.balance)
          : Number(walletItem?.available ?? 0) + consumed;

      const available =
        walletItem?.available !== undefined &&
        walletItem?.available !== null
          ? Number(walletItem.available)
          : balance - consumed;

      return {
        ...key,
        balance: Number.isFinite(balance) ? balance : 0,
        consumed: Number.isFinite(consumed) ? consumed : 0,
        available: Number.isFinite(available) ? available : 0,
      };
    });

    // 9. Send response
    return res.status(200).json({
      success: true,
      message: "All key settings fetched successfully",
      wallet_user_id: walletUserId,
      count: data.length,
      data,
    });
  } catch (error) {
    console.error("GET KEY SETTINGS ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to fetch key settings",
      error:
        process.env.NODE_ENV === "development"
          ? error.message
          : undefined,
    });
  }
};


//updated key-setting api
export const updateKeySetting = async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    if (!id) {
      return res.status(400).json({
        success: false,
        message: "Key setting id is required",
      });
    }

    if (status === undefined) {
      return res.status(400).json({
        success: false,
        message: "Status is required",
      });
    }

    const keySetting = await db("key_setting")
      .where("id", id)
      .first();

    if (!keySetting) {
      return res.status(404).json({
        success: false,
        message: "Key setting not found",
      });
    }

    const updateData = {
      status: Number(status) === 1 ? 1 : 0,
    };

    await db("key_setting")
      .where("id", id)
      .update(updateData);

    const updatedKeySetting = await db("key_setting")
      .where("id", id)
      .first();

    return res.status(200).json({
      success: true,
      message: "Key setting status updated successfully",
      data: updatedKeySetting,
    });
  } catch (error) {
    console.error(
      "UPDATE KEY SETTING STATUS ERROR:",
      error
    );

    return res.status(500).json({
      success: false,
      message: "Failed to update key setting status",
      error: error.message,
    });
  }
};

//post the transactione data





export const transferWalletPoints = async (req, res) => {
  let trx;

  const rollbackAndRespond = async (status, payload) => {
    if (trx) {
      try {
        await trx.rollback();
      } catch (error) {
        console.error("ROLLBACK ERROR:", error);
      }
      trx = null;
    }

    return res.status(status).json(payload);
  };

  const CHILD_ROLES = {
    0: [1],
    1: [2],
    2: [3],
    3: [4],
    4: [5],
    5: [6],
    6: [7, 8],
    7: [8],
  };

  const normalize = (value) =>
    String(value ?? "").trim().toLowerCase();

  // Handles JSON stored as a string, double-encoded JSON,
  // arrays, and objects keyed by key name.
  const parseWallet = (value) => {
    if (Buffer.isBuffer(value)) {
      value = value.toString("utf8");
    }

    if (value === null || value === undefined || value === "") {
      return [];
    }

    let parsed = value;

    for (let i = 0; i < 5 && typeof parsed === "string"; i++) {
      if (!parsed.trim()) return [];

      try {
        parsed = JSON.parse(parsed);
      } catch {
        return null;
      }
    }

    if (typeof parsed === "string") {
      return null;
    }

    if (Array.isArray(parsed)) {
      if (
        !parsed.every(
          (item) =>
            item !== null &&
            typeof item === "object" &&
            !Array.isArray(item)
        )
      ) {
        return null;
      }

      return parsed.filter(
        (item) =>
          !(
            item._legacy_single_balance === true &&
            item.name == null
          )
      );
    }

    if (parsed && typeof parsed === "object") {
      if (
        "key_setting_id" in parsed ||
        "keySettingId" in parsed ||
        "key_id" in parsed ||
        "keyId" in parsed ||
        "balance" in parsed ||
        "available" in parsed
      ) {
        return [parsed];
      }

      const entries = Object.entries(parsed);

      return entries.map(([name, entry]) => {
        if (
          entry &&
          typeof entry === "object" &&
          !Array.isArray(entry)
        ) {
          return {
            ...entry,
            name: entry.name ?? name,
          };
        }

        const amount = Number(entry);

        if (!Number.isFinite(amount) || amount < 0) {
          return {
            name,
            balance: NaN,
            consumed: 0,
            available: NaN,
          };
        }

        return {
          name,
          balance: amount,
          consumed: 0,
          available: amount,
        };
      });
    }

    return null;
  };

  const normalizeEntry = (item, keySetting) => {
    const consumed = Number(item?.consumed ?? 0);

    const balance =
      item?.balance !== undefined && item?.balance !== null
        ? Number(item.balance)
        : item?.available !== undefined && item?.available !== null
          ? Number(item.available) + consumed
          : Number(item?.amount ?? item?.points ?? 0);

    const available =
      item?.available !== undefined && item?.available !== null
        ? Number(item.available)
        : balance - consumed;

    if (
      !Number.isFinite(balance) ||
      !Number.isFinite(consumed) ||
      !Number.isFinite(available) ||
      balance < 0 ||
      consumed < 0 ||
      available < 0
    ) {
      return null;
    }

    return {
      ...item,
      key_setting_id: Number(keySetting.id),
      name: keySetting.name,
      balance,
      consumed,
      available,
    };
  };

  const findKeyIndex = (entries, keySetting) =>
    entries.findIndex((item) => {
      const rawId =
        item?.key_setting_id ??
        item?.keySettingId ??
        item?.key_id ??
        item?.keyId;

      if (rawId !== null && rawId !== undefined && rawId !== "") {
        return Number(rawId) === Number(keySetting.id);
      }

      return normalize(item?.name) === normalize(keySetting.name);
    });

  try {
    trx = await db.transaction();

    const actorId = Number(req.user?.id);

    const {
      to_user_id,
      key_setting_id,
      points_sent,
      transaction_type,
      transaction_pin,
    } = req.body;

    if (!Number.isInteger(actorId) || actorId <= 0) {
      return await rollbackAndRespond(401, {
        success: false,
        message: "Unauthorized user",
      });
    }

    const toUserId = Number(to_user_id);
    const keySettingId = Number(key_setting_id);
    const points = Number(points_sent);
    const transactionType = Number(transaction_type);

    if (!Number.isInteger(toUserId) || toUserId <= 0) {
      return await rollbackAndRespond(400, {
        success: false,
        message: "Valid receiver user ID is required",
      });
    }

    if (!Number.isInteger(keySettingId) || keySettingId <= 0) {
      return await rollbackAndRespond(400, {
        success: false,
        message: "Valid key setting ID is required",
      });
    }

    if (!Number.isFinite(points) || points <= 0) {
      return await rollbackAndRespond(400, {
        success: false,
        message: "Points must be greater than zero",
      });
    }

    if (![0, 1, 2].includes(transactionType)) {
      return await rollbackAndRespond(400, {
        success: false,
        message: "Invalid transaction type",
      });
    }

    if (
      transaction_pin == null ||
      String(transaction_pin).trim() === ""
    ) {
      return await rollbackAndRespond(400, {
        success: false,
        message: "Transaction PIN is required",
      });
    }

    const isRevert = transactionType === 2;

    // Lock the actor.
    const actor = await trx("users")
      .select(
        "id",
        "role_id",
        "parent_id",
        "created_by",
        "transaction_pin"
      )
      .where({ id: actorId })
      .forUpdate()
      .first();

    if (!actor) {
      return await rollbackAndRespond(404, {
        success: false,
        message: "Logged-in user not found",
      });
    }

    if (
      String(actor.transaction_pin ?? "").trim() !==
      String(transaction_pin).trim()
    ) {
      return await rollbackAndRespond(400, {
        success: false,
        message: "Invalid transaction PIN",
      });
    }

    const actorRoleId = Number(actor.role_id);

    // Staff uses its parent/creator account as wallet owner.
    const walletOwnerId =
      actorRoleId === 9
        ? Number(actor.created_by || actor.parent_id)
        : actorId;

    if (!Number.isInteger(walletOwnerId) || walletOwnerId <= 0) {
      return await rollbackAndRespond(400, {
        success: false,
        message: "Wallet owner account not found",
      });
    }

    if (toUserId === actorId || toUserId === walletOwnerId) {
      return await rollbackAndRespond(400, {
        success: false,
        message: "Invalid receiver selection",
      });
    }

    const keySetting = await trx("key_setting")
      .select("id", "name", "status")
      .where({ id: keySettingId })
      .first();

    if (!keySetting) {
      return await rollbackAndRespond(404, {
        success: false,
        message: "Key setting not found",
      });
    }

    if (Number(keySetting.status) !== 1) {
      return await rollbackAndRespond(400, {
        success: false,
        message: "Selected key setting is inactive",
      });
    }

    const walletOwner = await trx("users")
      .select("id", "role_id", "parent_id", "wallet_balance")
      .where({ id: walletOwnerId })
      .forUpdate()
      .first();

    if (!walletOwner) {
      return await rollbackAndRespond(404, {
        success: false,
        message: "Wallet owner not found",
      });
    }

    const receiver = await trx("users")
      .select("id", "role_id", "parent_id", "wallet_balance")
      .where({ id: toUserId })
      .forUpdate()
      .first();

    if (!receiver) {
      return await rollbackAndRespond(404, {
        success: false,
        message: "Receiver not found",
      });
    }

    const ownerRoleId = Number(walletOwner.role_id);
    const receiverRoleId = Number(receiver.role_id);

    // Require the receiver to be a direct child in the hierarchy.
    const allowedRoles = CHILD_ROLES[ownerRoleId] ?? [];

    if (Number(receiver.parent_id) !== walletOwnerId) {
      return await rollbackAndRespond(403, {
        success: false,
        message: "Receiver is not a direct child of the wallet owner",
        wallet_owner_id: walletOwnerId,
        receiver_id: toUserId,
      });
    }

    if (!allowedRoles.includes(receiverRoleId)) {
      return await rollbackAndRespond(403, {
        success: false,
        message: "Receiver role is not allowed for this transfer",
        wallet_owner_role_id: ownerRoleId,
        receiver_role_id: receiverRoleId,
        allowed_roles: allowedRoles,
      });
    }

    // Parse wallets and report which record is malformed.
    const ownerEntries = parseWallet(walletOwner.wallet_balance);
    const receiverEntries = parseWallet(receiver.wallet_balance);

    if (!ownerEntries || !receiverEntries) {
      console.error("INVALID WALLET FORMAT:", {
        walletOwnerId,
        ownerWalletType: typeof walletOwner.wallet_balance,
        ownerWalletValue: walletOwner.wallet_balance,
        receiverId: toUserId,
        receiverWalletType: typeof receiver.wallet_balance,
        receiverWalletValue: receiver.wallet_balance,
      });

      return await rollbackAndRespond(400, {
        success: false,
        message: "Invalid wallet balance format",
        wallet_owner_id: walletOwnerId,
        selected_user_id: toUserId,
      });
    }

    let ownerIndex = findKeyIndex(ownerEntries, keySetting);
    let receiverIndex = findKeyIndex(receiverEntries, keySetting);

    if (!isRevert && ownerIndex === -1) {
      return await rollbackAndRespond(400, {
        success: false,
        message: "Selected key is missing from wallet owner's wallet",
        wallet_owner_id: walletOwnerId,
        key_setting_id: keySettingId,
      });
    }

    if (isRevert && receiverIndex === -1) {
      return await rollbackAndRespond(400, {
        success: false,
        message: "Selected key is missing from receiver's wallet",
        receiver_id: toUserId,
        key_setting_id: keySettingId,
      });
    }

    if (receiverIndex === -1 && !isRevert) {
      receiverEntries.push({
        key_setting_id: keySettingId,
        name: keySetting.name,
        balance: 0,
        consumed: 0,
        available: 0,
      });

      receiverIndex = receiverEntries.length - 1;
    }

    if (ownerIndex === -1 && isRevert) {
      ownerEntries.push({
        key_setting_id: keySettingId,
        name: keySetting.name,
        balance: 0,
        consumed: 0,
        available: 0,
      });

      ownerIndex = ownerEntries.length - 1;
    }

    const ownerEntry = normalizeEntry(
      ownerEntries[ownerIndex],
      keySetting
    );

    const receiverEntry = normalizeEntry(
      receiverEntries[receiverIndex],
      keySetting
    );

    if (!ownerEntry || !receiverEntry) {
      return await rollbackAndRespond(400, {
        success: false,
        message: "Invalid wallet balance values",
        wallet_owner_id: walletOwnerId,
        selected_user_id: toUserId,
        key_setting_id: keySettingId,
      });
    }

    if (!isRevert && ownerEntry.available < points) {
      return await rollbackAndRespond(400, {
        success: false,
        message: "Insufficient wallet balance",
        wallet_owner_id: walletOwnerId,
        available_balance: ownerEntry.available,
        requested_points: points,
      });
    }

    if (
      isRevert &&
      (
        receiverEntry.available < points ||
        receiverEntry.balance < points ||
        ownerEntry.consumed < points
      )
    ) {
      return await rollbackAndRespond(400, {
        success: false,
        message: "Revert amount exceeds the transferable balance",
        receiver_available: receiverEntry.available,
        receiver_balance: receiverEntry.balance,
        owner_consumed: ownerEntry.consumed,
        requested_points: points,
      });
    }

    const ownerUpdated = {
      ...ownerEntry,
      consumed: isRevert
        ? ownerEntry.consumed - points
        : ownerEntry.consumed + points,
      available: isRevert
        ? ownerEntry.available + points
        : ownerEntry.available - points,
    };

    const receiverUpdated = {
      ...receiverEntry,
      balance: isRevert
        ? receiverEntry.balance - points
        : receiverEntry.balance + points,
      available: isRevert
        ? receiverEntry.available - points
        : receiverEntry.available + points,
    };

    ownerEntries[ownerIndex] = ownerUpdated;
    receiverEntries[receiverIndex] = receiverUpdated;

    await trx("users")
      .where({ id: walletOwnerId })
      .update({
        wallet_balance: JSON.stringify(ownerEntries),
      });

    await trx("users")
      .where({ id: toUserId })
      .update({
        wallet_balance: JSON.stringify(receiverEntries),
      });

    const [transactionId] = await trx("wallet").insert({
      from_user_id: walletOwnerId,
      to_user_id: toUserId,
      key_setting_id: keySettingId,
      points_sent: points,
      from_balance_before: ownerEntry.available,
      from_balance_after: ownerUpdated.available,
      to_balance_before: receiverEntry.available,
      to_balance_after: receiverUpdated.available,
      transaction_type: transactionType,
      created_by: actorId,
    });

    await trx.commit();
    trx = null;

    return res.status(200).json({
      success: true,
      message: isRevert
        ? "Points reverted successfully"
        : "Points transferred successfully",
      data: {
        transaction_id: transactionId,
        actor_id: actorId,
        wallet_owner_id: walletOwnerId,
        to_user_id: toUserId,
        key_setting_id: keySettingId,
        key_name: keySetting.name,
        points_sent: points,
        transaction_type: transactionType,
        from_balance_before: ownerEntry.available,
        from_balance_after: ownerUpdated.available,
        from_consumed_before: ownerEntry.consumed,
        from_consumed_after: ownerUpdated.consumed,
        to_balance_before: receiverEntry.available,
        to_balance_after: receiverUpdated.available,
        wallet_owner_wallet: ownerUpdated,
        receiver_wallet: receiverUpdated,
      },
    });
  } catch (error) {
    if (trx) {
      try {
        await trx.rollback();
      } catch (rollbackError) {
        console.error("ROLLBACK ERROR:", rollbackError);
      }

      trx = null;
    }

    console.error("TRANSFER WALLET POINTS ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to process wallet points",
      error:
        process.env.NODE_ENV === "development"
          ? error.message
          : undefined,
    });
  }
};


//get the transactione data

export const getWalletTransactions = async (req, res) => {
  try {
    const userId = Number(req.user?.id);
    const roleId = Number(req.user?.role_id);

    // 1. Validate logged-in user
    if (
      !Number.isInteger(userId) ||
      userId <= 0 ||
      !Number.isInteger(roleId)
    ) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized",
      });
    }

    // 2. Read query parameters
    const {
      page = 1,
      limit = 10,
      transaction_type,
      key_setting_id,
    } = req.query;

    const pageNumber = Math.max(
      parseInt(page, 10) || 1,
      1
    );

    const limitNumber = Math.min(
      Math.max(parseInt(limit, 10) || 10, 1),
      100
    );

    const offset = (pageNumber - 1) * limitNumber;

    // 3. Verify Staff account
    if (roleId === 9) {
      const staff = await db("users")
        .select("id")
        .where("id", userId)
        .where("role_id", 9)
        .first();

      if (!staff) {
        return res.status(404).json({
          success: false,
          message: "Staff user not found",
        });
      }
    }

    // 4. Base wallet transactions query
    const query = db("wallet as wt")
      .leftJoin(
        "users as from_user",
        "from_user.id",
        "wt.from_user_id"
      )
      .leftJoin(
        "users as to_user",
        "to_user.id",
        "wt.to_user_id"
      )
      .leftJoin(
        "users as actor",
        "actor.id",
        "wt.created_by"
      )
      .leftJoin(
        "key_setting as ks",
        "ks.id",
        "wt.key_setting_id"
      );

    /*
     * Role 0: All transactions.
     * Role 1: All transactions.
     * Role 9: All transactions.
     * Other roles: Transactions involving themselves.
     */
    if (roleId !== 0 && roleId !== 1 && roleId !== 9) {
      query.where(function () {
        this.where("wt.from_user_id", userId)
          .orWhere("wt.to_user_id", userId);
      });
    }

    // 5. Transaction type filter
    if (
      transaction_type !== undefined &&
      transaction_type !== ""
    ) {
      const type = Number(transaction_type);

      if (!Number.isInteger(type)) {
        return res.status(400).json({
          success: false,
          message: "Invalid transaction_type",
        });
      }

      query.where("wt.transaction_type", type);
    }

    // 6. Key setting filter
    if (
      key_setting_id !== undefined &&
      key_setting_id !== ""
    ) {
      const keySettingId = Number(key_setting_id);

      if (
        !Number.isInteger(keySettingId) ||
        keySettingId <= 0
      ) {
        return res.status(400).json({
          success: false,
          message: "Invalid key_setting_id",
        });
      }

      query.where("wt.key_setting_id", keySettingId);
    }

    // 7. Count total transactions
    const countResult = await query
      .clone()
      .countDistinct({ total: "wt.id" })
      .first();

    const total = Number(countResult?.total || 0);

    // 8. Fetch paginated transaction history
    const transactions = await query
      .clone()
      .select(
        "wt.*",

        // Use the actual transaction sender.
        "from_user.name as from_user_name",
        "from_user.email as from_user_email",
        "from_user.role_id as from_user_role_id",

        // Use the actual transaction receiver.
        "to_user.name as to_user_name",
        "to_user.email as to_user_email",
        "to_user.role_id as to_user_role_id",

        // Keep the transaction creator separately.
        "actor.name as actor_name",
        "actor.role_id as actor_role_id",

        "ks.name as key_setting_name"
      )
      .orderBy("wt.created_at", "desc")
      .orderBy("wt.id", "desc")
      .limit(limitNumber)
      .offset(offset);

    // 9. API response
    return res.status(200).json({
      success: true,
      message: "Wallet transactions fetched successfully",
      data: transactions,
      pagination: {
        page: pageNumber,
        limit: limitNumber,
        total,
        totalPages: Math.ceil(total / limitNumber),
      },
    });
  } catch (error) {
    console.error(
      "GET WALLET TRANSACTIONS ERROR:",
      error
    );

    return res.status(500).json({
      success: false,
      message: "Failed to fetch wallet transactions",
      error: error.message,
    });
  }
};


//company setting  name and logo
export const addCompanySetting = async (req, res) => {
  try {
    const { key, value } = req.body;

    if (!key || !key.trim()) {
      return res.status(400).json({
        success: false,
        message: "Key is required",
      });
    }

    if (
      value === undefined ||
      value === null ||
      !String(value).trim()
    ) {
      return res.status(400).json({
        success: false,
        message: "Value is required",
      });
    }

    const cleanKey = key.trim().toLowerCase();
    const cleanValue = String(value).trim();

    const [settingId] = await db("companysetting").insert({
      key: cleanKey,
      value: cleanValue,
    });

    const companySetting = await db("companysetting")
      .where("id", settingId)
      .select("id", "key", "value")
      .first();

    return res.status(201).json({
      success: true,
      message: "Company setting added successfully",
      data: companySetting,
    });
  } catch (error) {
    console.error("Add Company Setting Error:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to add company setting",
      error: error.message,
    });
  }
};
//company setting get data
export const getCompanySetting = async (req, res) => {
  try {
    const roleId = Number(req.user?.role_id);

    if (Number.isNaN(roleId)) {
      return res.status(401).json({
        success: false,
        message: "Invalid user role",
      });
    }

    const companySettings = await db("companysetting")
      .where(function () {
        this.where("role_id", roleId)
          .orWhere(function () {
            this.where("role_id", 0)
              .andWhere(function () {
                this.where("key", "maintenance")
                  .orWhere("key", "suspend");
              });
          });
      })
      .select(
        "id",
        "key",
        "value",
        "role_id",
        "created_at",
        "updated_at"
      )
      .orderBy("id", "asc");

    return res.status(200).json({
      success: true,
      message: "Company setting fetched successfully",
      data: companySettings,
    });
  } catch (error) {
    console.error("Get Company Setting Error:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to fetch company setting",
      error: error.message,
    });
  }
};

export const getNormalCompanySetting = async (req, res) => {
  try {
    const companySettings = await db("companysetting")
      .whereIn("key", ["company_name", "company_logo"])
      .select("id", "key", "value", "role_id")
      .orderBy("id", "asc");

    const settings = {
      company_name: "",
      company_logo: null,
    };

    companySettings.forEach((item) => {
      settings[item.key] = item.value;
    });

    return res.status(200).json({
      success: true,
      message: "Company setting fetched successfully",
      data: settings,
    });
  } catch (error) {
    console.error("Get Company Setting Error:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to fetch company setting",
      error: error.message,
    });
  }
};


// update company setting get data
export const updateCompanySetting = async (req, res) => {
  try {
    const roleId = Number(req.user?.role_id);
    const { key, value } = req.body;

    if (Number.isNaN(roleId)) {
      return res.status(401).json({
        success: false,
        message: "Invalid user role",
      });
    }

    if (!key || !key.trim()) {
      return res.status(400).json({
        success: false,
        message: "Key is required",
      });
    }

    const cleanKey = key.trim().toLowerCase();

    let cleanValue = value;

    if (req.file) {
      cleanValue = `/uploads/modules/${req.file.filename}`;
    }

    const booleanKeys = ["maintenance", "suspend"];

    if (booleanKeys.includes(cleanKey)) {
      if (
        value === true ||
        value === "true" ||
        value === 1 ||
        value === "1"
      ) {
        cleanValue = 1;
      } else if (
        value === false ||
        value === "false" ||
        value === 0 ||
        value === "0"
      ) {
        cleanValue = 0;
      } else {
        return res.status(400).json({
          success: false,
          message: "Boolean value must be true or false",
        });
      }
    } else {
      if (
        cleanValue === undefined ||
        cleanValue === null ||
        !String(cleanValue).trim()
      ) {
        return res.status(400).json({
          success: false,
          message: "Value is required",
        });
      }

      cleanValue = String(cleanValue).trim();
    }

    const existingSetting = await db("companysetting")
      .where("key", cleanKey)
      .where("role_id", roleId)
      .first();

    if (existingSetting) {
      await db("companysetting")
        .where("id", existingSetting.id)
        .update({
          value: cleanValue,
        });
    } else {
      await db("companysetting").insert({
        key: cleanKey,
        value: cleanValue,
        role_id: roleId,
      });
    }

    const updatedSetting = await db("companysetting")
      .where("key", cleanKey)
      .where("role_id", roleId)
      .select(
        "id",
        "key",
        "value",
        "role_id",
        "created_at",
        "updated_at"
      )
      .first();

    return res.status(200).json({
      success: true,
      message: "Company setting updated successfully",
      data: updatedSetting,
    });
  } catch (error) {
    console.error("Update Company Setting Error:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to update company setting",
      error: error.message,
    });
  }
};


// add-device / user list


export const addDevice = async (req, res) => {
  try {
    // 1. Get token from Authorization header
    const authHeader = req.headers.authorization;

    if (!authHeader?.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Authentication token is missing.",
      });
    }

    const token = authHeader.slice(7).trim();

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Authentication token is missing.",
      });
    }

    // 2. Verify token
    if (!process.env.JWT_SECRET) {
      console.error("JWT_SECRET is missing.");

      return res.status(500).json({
        success: false,
        message: "Authentication configuration error.",
      });
    }

    let decoded;

    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch {
      return res.status(401).json({
        success: false,
        message: "Invalid or expired token. Please login again.",
      });
    }

    // 3. Extract logged-in user's ID from token
    const loggedInUserId =
      decoded.id ??
      decoded.user_id ??
      decoded.userId;

    if (
      loggedInUserId === undefined ||
      loggedInUserId === null ||
      String(loggedInUserId).trim() === ""
    ) {
      return res.status(401).json({
        success: false,
        message: "User ID not found in token.",
      });
    }

    // 4. Verify user in database
    const user = await db("users")
      .select("id")
      .where("id", loggedInUserId)
      .first();

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Logged-in user not found.",
      });
    }

    // 5. Read request fields
    const {
      enrollment_type,
      customer_name,
      registration_no,
      phone_number,
      imei_1,
      key_type,
      device_status,
      fl_version,
    } = req.body;

    // 6. Get uploaded image files
    const brandFile =
      req.files?.brand?.[0] ||
      req.files?.brandImage?.[0];

    const customerImageFile =
      req.files?.customer_image?.[0] ||
      req.files?.customerImage?.[0];

    // 7. Validate required fields
    const requiredFields = {
      enrollment_type,
      customer_name,
      registration_no,
      phone_number,
      imei_1,
      key_type,
      device_status,
      fl_version,
    };

    const missingFields = Object.entries(requiredFields)
      .filter(
        ([, value]) =>
          value === undefined ||
          value === null ||
          String(value).trim() === ""
      )
      .map(([key]) => key);

    if (missingFields.length > 0) {
      return res.status(400).json({
        success: false,
        message: "Please provide all required fields.",
        missingFields,
      });
    }

    // 8. Validate enrollment type
    const normalizedEnrollmentType = String(enrollment_type)
      .trim()
      .toLowerCase();

    if (!["old", "new"].includes(normalizedEnrollmentType)) {
      return res.status(400).json({
        success: false,
        message: "enrollment_type must be either 'old' or 'new'.",
      });
    }

    // 9. Validate images
    if (!brandFile || !customerImageFile) {
      return res.status(400).json({
        success: false,
        message: "Both brand and customer images are required.",
      });
    }

    const brand = `/uploads/devices/${brandFile.filename}`;
    const customer_image = `/uploads/devices/${customerImageFile.filename}`;

    // 10. Prepare database values
    const deviceData = {
      created_by: user.id,
      brand,
      enrollment_type: normalizedEnrollmentType,
      customer_name: String(customer_name).trim(),
      customer_image,
      registration_no: String(registration_no).trim(),
      phone_number: String(phone_number).trim(),
      imei_1: String(imei_1).trim(),
      key_type,
      device_status,
      fl_version,
      created_at: db.fn.now(),
    };

    // 11. Insert device into database
    const insertResult = await db("device_detail").insert(deviceData);

    const deviceId = Array.isArray(insertResult)
      ? insertResult[0]
      : insertResult;

    // 12. Return only plain JSON values
    return res.status(201).json({
      success: true,
      message: "Device added successfully.",
      data: {
        id: deviceId,
        created_by: user.id,
        brand,
        enrollment_type: normalizedEnrollmentType,
        customer_name: deviceData.customer_name,
        customer_image,
        registration_no: deviceData.registration_no,
        phone_number: deviceData.phone_number,
        imei_1: deviceData.imei_1,
        key_type,
        device_status,
        fl_version,
      },
    });
  } catch (error) {
    console.error(
      "ADD DEVICE ERROR:",
      error?.stack || error?.message || String(error)
    );

    return res.status(500).json({
      success: false,
      message: "Failed to add device.",
      error: error?.message || "Internal server error",
    });
  }
};

// GET all devices

export const getDevices = async (req, res) => {
  try {
    const devices = await db("device_detail as d")
      // User who added the device (Retailer)
      .leftJoin("users as retailer", "d.created_by", "retailer.id")

      // Retailer's parent (FOS)
      .leftJoin("users as fos", "retailer.parent_id", "fos.id")

      // FOS's parent (Distributor)
      .leftJoin("users as distributor", "fos.parent_id", "distributor.id")

      .select(
        "d.*",

        // Retailer details
        "retailer.id as retailer_id",
        "retailer.name as retailer_name",
        "retailer.organization_name as retailer_company_name",

        // FOS details
        "fos.id as fos_id",
        "fos.name as fos_name",
        "fos.organization_name as fos_company_name",

        // Distributor details
        "distributor.id as distributor_id",
        "distributor.name as distributor_name",
        "distributor.organization_name as distributor_company_name"
      )
      .orderBy("d.id", "desc");

    return res.status(200).json({
      success: true,
      message: "Devices fetched successfully.",
      count: devices.length,
      data: devices,
    });
  } catch (error) {
    console.error(
      "GET DEVICES ERROR:",
      error?.stack || error?.message || error
    );

    return res.status(500).json({
      success: false,
      message: "Failed to fetch devices.",
      error: error?.message || "Internal server error",
    });
  }
};


// GET single device by ID
export const getDeviceById = async (req, res) => {
  try {
    const { id } = req.params;

    // Validate device ID
    if (!id || !/^\d+$/.test(String(id))) {
      return res.status(400).json({
        success: false,
        message: "Invalid device ID.",
      });
    }

    const deviceId = Number(id);

    if (!Number.isSafeInteger(deviceId) || deviceId <= 0) {
      return res.status(400).json({
        success: false,
        message: "Device ID must be a positive integer.",
      });
    }

    // Fetch complete device data and related hierarchy details
    const device = await db("device_detail as d")
      .leftJoin("users as retailer", "d.created_by", "retailer.id")
      .leftJoin("users as fos", "retailer.parent_id", "fos.id")
      .leftJoin("users as distributor", "fos.parent_id", "distributor.id")
      .select(
        // All device_detail columns
        "d.*",

        // Retailer details
        "retailer.id as retailer_id",
        "retailer.name as retailer_name",
        "retailer.organization_name as retailer_company_name",
        "retailer.parent_id as retailer_parent_id",

        // FOS details
        "fos.id as fos_id",
        "fos.name as fos_name",
        "fos.organization_name as fos_company_name",
        "fos.parent_id as fos_parent_id",

        // Distributor details
        "distributor.id as distributor_id",
        "distributor.name as distributor_name",
        "distributor.organization_name as distributor_company_name",
        "distributor.parent_id as distributor_parent_id"
      )
      .where("d.id", deviceId)
      .first();

    if (!device) {
      return res.status(404).json({
        success: false,
        message: "Device not found.",
        data: null,
      });
    }

    return res.status(200).json({
      success: true,
      message: "Device fetched successfully.",
      data: device,
    });
  } catch (error) {
    console.error(
      "GET DEVICE BY ID ERROR:",
      error?.stack || error?.message || error
    );

    return res.status(500).json({
      success: false,
      message: "Failed to fetch device.",
      error:
        process.env.NODE_ENV === "development"
          ? error?.message
          : "Internal server error",
    });
  }
};

