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

// ADD STAFF





export const createuserrole = async (req, res) => {
    try {
        const {
            organization_name,
            role_id,
            parent_id,
            name,
            email,
            phone,
            password,
            confirm_password,
            company_address,
            country,
            state,
            city,
            new_device,
            old_device,
            supreme_device,
            pro_star,
            lite,
            google_tv,
            supreme_lock,
            role_permission
        } = req.body;

        if (!name || !email || !phone || !password || !confirm_password) {
            return res.status(400).json({
                success: false,
                message: "Name, email, phone, password and confirm password are required"
            });
        }

        if (password !== confirm_password) {
            return res.status(400).json({
                success: false,
                message: "Password and confirm password do not match"
            });
        }

        const phoneValue = String(phone).trim().replace(/\s+/g, "");

        let normalizedPhone = phoneValue;

        if (phoneValue.startsWith("+91")) {
            normalizedPhone = phoneValue.slice(3);
        } else if (phoneValue.startsWith("91") && phoneValue.length === 12) {
            normalizedPhone = phoneValue.slice(2);
        }

        if (!/^[6-9]\d{9}$/.test(normalizedPhone)) {
            return res.status(400).json({
                success: false,
                message: "Invalid phone number"
            });
        }

        const requestedRoleId = Number(role_id);

        if (Number.isNaN(requestedRoleId)) {
            return res.status(400).json({
                success: false,
                message: "Valid role_id is required"
            });
        }

        if (requestedRoleId === 0) {
            return res.status(403).json({
                success: false,
                message: "Master Admin cannot be created"
            });
        }

        if (!req.user || !req.user.id) {
            return res.status(401).json({
                success: false,
                message: "Unauthorized"
            });
        }

        const created_by = Number(req.user.id);

        const creator = await db("users")
            .where("id", created_by)
            .first();

        if (!creator) {
            return res.status(404).json({
                success: false,
                message: "Creator not found"
            });
        }

        const creatorRole = Number(creator.role_id);

        if (requestedRoleId <= creatorRole) {
            return res.status(403).json({
                success: false,
                message: "You are not allowed to create this role"
            });
        }

        const parentRoles = {
            2: [1],
            3: [2],
            4: [2, 3],
            5: [2, 3, 4],
            6: [2, 3, 4, 5],
            7: [2, 3, 4, 5, 6],
            8: [2, 3, 4, 5, 6, 7],
            9: [1]
        };

        if (requestedRoleId === 9 && creatorRole !== 1) {
            return res.status(403).json({
                success: false,
                message: "Only Admin can create Staff"
            });
        }

        if (creatorRole === 8 || creatorRole === 9) {
            return res.status(403).json({
                success: false,
                message: "Employee and Staff cannot create users"
            });
        }

        const allowedParentRoles = parentRoles[requestedRoleId] || [];

        const finalParentId =
            parent_id !== undefined &&
            parent_id !== null &&
            parent_id !== ""
                ? Number(parent_id)
                : null;

        if (finalParentId !== null) {
            const parentUser = await db("users")
                .where("id", finalParentId)
                .first();

            if (!parentUser) {
                return res.status(404).json({
                    success: false,
                    message: "Parent user not found"
                });
            }

            if (!allowedParentRoles.includes(Number(parentUser.role_id))) {
                return res.status(400).json({
                    success: false,
                    message: "Invalid parent role"
                });
            }
        }

        const existingEmail = await db("users")
            .where("email", email)
            .first();

        if (existingEmail) {
            return res.status(409).json({
                success: false,
                message: "Email already exists"
            });
        }

        const existingPhone = await db("users")
            .where("phone", normalizedPhone)
            .first();

        if (existingPhone) {
            return res.status(409).json({
                success: false,
                message: "Phone number already exists"
            });
        }

        if (requestedRoleId === 6) {
            const deviceFields = [
                new_device,
                old_device,
                supreme_device,
                pro_star,
                lite,
                google_tv,
                supreme_lock
            ];

            const hasDevicePermission = deviceFields.some(
                value => Number(value) === 1
            );

            if (!hasDevicePermission) {
                return res.status(400).json({
                    success: false,
                    message: "At least one device permission is required for Retailer"
                });
            }
        }

        let parsedRolePermission = [];

        if (
            role_permission !== undefined &&
            role_permission !== null &&
            role_permission !== ""
        ) {
            try {
                parsedRolePermission =
                    typeof role_permission === "string"
                        ? JSON.parse(role_permission)
                        : role_permission;
            } catch (error) {
                return res.status(400).json({
                    success: false,
                    message: "Invalid role_permission format"
                });
            }

            if (!Array.isArray(parsedRolePermission)) {
                parsedRolePermission = [parsedRolePermission];
            }

            const moduleMap = new Map();

            parsedRolePermission.forEach(item => {
                if (!item || !item.module_id) {
                    return;
                }

                const moduleId = Number(item.module_id);

                if (!moduleMap.has(moduleId)) {
                    moduleMap.set(moduleId, {
                        module_id: moduleId,
                        sub_modules: {
                            manage: 0,
                            edit: 0,
                            view: 0,
                            add: 0,
                            delete: 0
                        },
                        given_by: created_by,
                        given_by_role: creatorRole,
                        given_at: new Date().toISOString()
                    });
                }

                const moduleData = moduleMap.get(moduleId);

                if (
                    item.sub_modules &&
                    typeof item.sub_modules === "object"
                ) {
                    const subModules = item.sub_modules;

                    moduleData.sub_modules.manage =
                        Number(subModules.manage) === 1 ? 1 : 0;

                    moduleData.sub_modules.edit =
                        Number(subModules.edit) === 1 ? 1 : 0;

                    moduleData.sub_modules.view =
                        Number(subModules.view) === 1 ? 1 : 0;

                    moduleData.sub_modules.add =
                        Number(subModules.add) === 1 ? 1 : 0;

                    moduleData.sub_modules.delete =
                        Number(subModules.delete) === 1 ? 1 : 0;
                }
            });

            parsedRolePermission = Array.from(moduleMap.values());
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const userData = {
            organization_name: organization_name || null,
            role_id: requestedRoleId,
            parent_id: finalParentId,
            name,
            email,
            phone: normalizedPhone,
            password: hashedPassword,
            company_address: company_address || null,
            country: country || null,
            state: state || null,
            city: city || null,
            new_device: Number(new_device) || 0,
            old_device: Number(old_device) || 0,
            supreme_device: Number(supreme_device) || 0,
            pro_star: Number(pro_star) || 0,
            lite: Number(lite) || 0,
            google_tv: Number(google_tv) || 0,
            supreme_lock: Number(supreme_lock) || 0,
            created_by,
            role_permission: parsedRolePermission
        };

        const userId = await createUserModel(userData);

        return res.status(201).json({
            success: true,
            message: "User created successfully",
            data: {
                id: userId,
                organization_name: organization_name || null,
                role_id: requestedRoleId,
                parent_id: finalParentId,
                name,
                email,
                phone: normalizedPhone,
                company_address: company_address || null,
                country: country || null,
                state: state || null,
                city: city || null,
                role_permission: parsedRolePermission
            }
        });
    } catch (error) {
        console.error("CREATE USER ROLE ERROR:", error);

        return res.status(500).json({
            success: false,
            message: "Internal server error"
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

    const match = await bcrypt.compare(
      password,
      user.password
    );

    if (!match) {
      return res.status(401).json({
        success: false,
        message: "Invalid password",
      });
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

    return res.status(200).json({
      success: true,
      message: "Login Successful",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role_id: user.role_id,
        userStatus: Number(user.userStatus),
        parent_id: user.parent_id,
        parent_admin_id: user.parent_admin_id,
        parent_cnf_id: user.parent_cnf_id,
        parent_super_distributor_id:
          user.parent_super_distributor_id,
        parent_distributor_id:
          user.parent_distributor_id,
        parent_fos_id: user.parent_fos_id,
        parent_retailer_id:
          user.parent_retailer_id,
        parent_employee_id:
          user.parent_employee_id,
        parent_staff_id:
          user.parent_staff_id,
      },
    });
  } catch (error) {
    console.error("LOGIN ERROR:", error);

    return res.status(500).json({
      success: false,
      message: error.message || "Internal server error",
    });
  }
};

// GET ALL USERS
export const getUsers = async (req, res) => {
  try {
    const page = Math.max(Number(req.query.page) || 1, 1);
    const limit = Math.max(Number(req.query.limit) || 10, 1);
    const offset = (page - 1) * limit;

    let role_id = null;

    if (req.query.role_id !== undefined && req.query.role_id !== "") {
      role_id = Number(req.query.role_id);

      if (!Number.isInteger(role_id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid role_id",
        });
      }
    }

    const search =
      req.query.search !== undefined &&
      String(req.query.search).trim() !== ""
        ? String(req.query.search).trim()
        : null;

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

    let status = null;

    if (
      req.query.status !== undefined &&
      String(req.query.status).trim() !== ""
    ) {
      const statusValue = String(req.query.status).trim().toLowerCase();

      if (statusValue === "active" || statusValue === "1") {
        status = 1;
      } else if (statusValue === "inactive" || statusValue === "0") {
        status = 0;
      } else {
        return res.status(400).json({
          success: false,
          message: "Invalid status",
        });
      }
    }

    const loggedInUserId = Number(req.user?.id);
    const loggedInRoleId = Number(req.user?.role_id);

    if (!Number.isInteger(loggedInUserId) || loggedInUserId <= 0) {
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
      status
    );

    const users = result.users.map(user => {
      let role_permission = [];

      if (user.role_permission) {
        try {
          role_permission =
            typeof user.role_permission === "string"
              ? JSON.parse(user.role_permission)
              : user.role_permission;

          if (!Array.isArray(role_permission)) {
            role_permission = [];
          }
        } catch (error) {
          role_permission = [];
        }
      }

      return {
        ...user,
        role_permission,
      };
    });

    return res.status(200).json({
      success: true,
      pagination: {
        currentPage: page,
        totalPages: Math.ceil(result.total / limit),
        limit,
        totalUsers: result.total,
      },
      data: users,
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
    const {
      organization_name,
      role_id,
      name,
      email,
      phone,
      company_address,
      country,
      state,
      city,
      parent_id,
      parent_hierarchy,
      new_device,
      old_device,
      supreme_device,
      pro_star,
      lite,
      google_tv,
      supreme_lock,
      password,
    } = req.body;

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

    const existingUser = await db("users")
      .select("id", "role_id", "parent_id")
      .where("id", userId)
      .first();

    if (!existingUser) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
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

    let normalizedParentId = existingUser.parent_id ?? null;

    if (parent_id !== undefined) {
      if (parent_id === null || parent_id === "") {
        normalizedParentId = null;
      } else {
        normalizedParentId = Number(parent_id);

        if (
          !Number.isInteger(normalizedParentId) ||
          normalizedParentId <= 0
        ) {
          return res.status(400).json({
            success: false,
            message: "Invalid parent ID",
          });
        }

        if (normalizedParentId === userId) {
          return res.status(400).json({
            success: false,
            message: "User cannot be their own parent",
          });
        }

        const parentUser = await db("users")
          .select(
            "id",
            "role_id",
            "name",
            "organization_name"
          )
          .where("id", normalizedParentId)
          .first();

        if (!parentUser) {
          return res.status(400).json({
            success: false,
            message: "Selected parent not found",
          });
        }

        const selectedParentRoleId = Number(
          parentUser.role_id
        );

        if (selectedParentRoleId >= currentRoleId) {
          return res.status(400).json({
            success: false,
            message: "Selected parent role is invalid",
          });
        }
      }
    }

    return await db.transaction(async (trx) => {
      const updateData = {
        organization_name: organization_name || "",
        role_id: currentRoleId,
        name: name || "",
        email: email || "",
        phone: phone || "",
        company_address: company_address || "",
        country: country || "",
        state: state || "",
        city: city || "",
        parent_id: normalizedParentId,
        new_device: Number(new_device ?? 0),
        old_device: Number(old_device ?? 0),
        supreme_device: Number(supreme_device ?? 0),
        pro_star: Number(pro_star ?? 0),
        lite: Number(lite ?? 0),
        google_tv: Number(google_tv ?? 0),
        supreme_lock: Number(supreme_lock ?? 0),
      };

      if (
        password !== undefined &&
        password !== null &&
        password !== ""
      ) {
        updateData.password = password;
      }

      await trx("users")
        .where("id", userId)
        .update(updateData);

      const updatedUser = await trx("users")
        .select(
          "id",
          "organization_name",
          "role_id",
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

      return res.status(200).json({
        success: true,
        message: "Staff data updated successfully",
        data: updatedUser,
      });
    });
  } catch (error) {
    console.error("UPDATE STAFF ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to update staff data",
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

    const user = await db("users")
      .select(
        "id",
        "organization_name",
        "role_id",
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
        "supreme_lock"
      )
      .where("id", userId)
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

    const targetUser = await db("users")
      .select(
        "id",
        "name",
        "email",
        "role_id",
        "parent_id"
      )
      .where("id", user_id)
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
        const { status } = req.body;

        if (!id) {
            return res.status(400).json({
                success: false,
                message: "Module ID is required"
            });
        }

        if (status === undefined || status === null) {
            return res.status(400).json({
                success: false,
                message: "Status is required"
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
        console.error("UPDATE MODULE STATUS ERROR:", error);

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



//role-permissions
export const updateRolePermissions = async (req, res) => {
    try {
        const { userId } = req.params;
        const { permissions } = req.body;

        if (!userId) {
            return res.status(400).json({
                success: false,
                message: "User ID is required"
            });
        }

        if (!Array.isArray(permissions)) {
            return res.status(400).json({
                success: false,
                message: "Permissions must be an array"
            });
        }

        const user = await db("users")
            .select("id", "role_id")
            .where("id", userId)
            .first();

        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        const formattedPermissions = permissions.map((permission) => ({
            module: String(permission?.module || "").trim().toLowerCase(),
            view: Number(permission?.view) === 1 ? 1 : 0,
            create: Number(permission?.create) === 1 ? 1 : 0,
            edit: Number(permission?.edit) === 1 ? 1 : 0,
            delete: Number(permission?.delete) === 1 ? 1 : 0
        }));

        const invalidModule = formattedPermissions.some(
            (permission) => !permission.module
        );

        if (invalidModule) {
            return res.status(400).json({
                success: false,
                message: "Module name is required"
            });
        }

        await db("users")
            .where("id", userId)
            .update({
                role_permission: JSON.stringify(formattedPermissions)
            });

        return res.status(200).json({
            success: true,
            message: "Role permissions updated successfully",
            data: {
                user_id: Number(userId),
                role_id: user.role_id,
                role_permission: formattedPermissions
            }
        });
    } catch (error) {
        console.error("UPDATE ROLE PERMISSIONS ERROR:", error);

        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
};