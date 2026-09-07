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
    } = req.body;

    if (!name || !String(name).trim()) {
      return res.status(400).json({
        success: false,
        message: "Name is required",
      });
    }

    if (!email || !String(email).trim()) {
      return res.status(400).json({
        success: false,
        message: "Email is required",
      });
    }

    if (!phone || !String(phone).trim()) {
      return res.status(400).json({
        success: false,
        message: "Phone number is required",
      });
    }

    if (!password) {
      return res.status(400).json({
        success: false,
        message: "Password is required",
      });
    }

    if (!confirm_password) {
      return res.status(400).json({
        success: false,
        message: "Confirm Password is required",
      });
    }

    if (password !== confirm_password) {
      return res.status(400).json({
        success: false,
        message: "Password and Confirm Password not match",
      });
    }

    const cleanName = String(name).trim();
    const cleanEmail = String(email).trim().toLowerCase();

    let cleanPhone = String(phone)
      .trim()
      .replace(/[\s\-()]/g, "");

    if (cleanPhone.startsWith("+91")) {
      const indianNumber = cleanPhone.substring(3);

      if (!/^[6-9]\d{9}$/.test(indianNumber)) {
        return res.status(400).json({
          success: false,
          message:
            "Invalid phone number. +91 ke baad 10 digit valid mobile number enter karein",
        });
      }

      cleanPhone = `+91${indianNumber}`;
    } else if (/^91[6-9]\d{9}$/.test(cleanPhone)) {
      cleanPhone = `+91${cleanPhone.substring(2)}`;
    } else if (/^[6-9]\d{9}$/.test(cleanPhone)) {
      cleanPhone = `+91${cleanPhone}`;
    } else {
      return res.status(400).json({
        success: false,
        message:
          "Invalid phone number. Valid 10 digit mobile number ya +91 ke saath number enter karein",
      });
    }

    const role = Number(role_id);

    if (!Number.isInteger(role) || !isValidRole(role)) {
      return res.status(400).json({
        success: false,
        message: "Invalid role_id",
      });
    }

    if (role === ROLES.MASTER_ADMIN) {
      return res.status(403).json({
        success: false,
        message: "Master Admin cannot be created",
      });
    }

    if (!req.user?.id) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized",
      });
    }

    const created_by = Number(req.user.id);

    if (!Number.isInteger(created_by) || created_by <= 0) {
      return res.status(401).json({
        success: false,
        message: "Invalid logged-in user",
      });
    }

    const creator = await findUserById(created_by);

    if (!creator) {
      return res.status(404).json({
        success: false,
        message: "Creator not found",
      });
    }

    const creatorRole = Number(creator.role_id);

    let selectedParentId = null;

    if (
      parent_id !== undefined &&
      parent_id !== null &&
      String(parent_id).trim() !== ""
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

      if (selectedParentId === created_by) {
        if (role === ROLES.STAFF && creatorRole === ROLES.ADMIN) {
          selectedParentId = created_by;
        }
      }
    }

    const allowedParentRoles = {
      [ROLES.CNF]: [ROLES.ADMIN],
      [ROLES.SUPER_DISTRIBUTOR]: [
        ROLES.ADMIN,
        ROLES.CNF,
      ],
      [ROLES.DISTRIBUTOR]: [
        ROLES.ADMIN,
        ROLES.CNF,
        ROLES.SUPER_DISTRIBUTOR,
      ],
      [ROLES.FOS]: [
        ROLES.ADMIN,
        ROLES.CNF,
        ROLES.SUPER_DISTRIBUTOR,
        ROLES.DISTRIBUTOR,
      ],
      [ROLES.RETAILER]: [
        ROLES.ADMIN,
        ROLES.CNF,
        ROLES.SUPER_DISTRIBUTOR,
        ROLES.DISTRIBUTOR,
        ROLES.FOS,
      ],
      [ROLES.SUB_RETAILER]: [
        ROLES.ADMIN,
        ROLES.CNF,
        ROLES.SUPER_DISTRIBUTOR,
        ROLES.DISTRIBUTOR,
        ROLES.FOS,
        ROLES.RETAILER,
      ],
      [ROLES.EMPLOYEE]: [
        ROLES.ADMIN,
        ROLES.CNF,
        ROLES.SUPER_DISTRIBUTOR,
        ROLES.DISTRIBUTOR,
        ROLES.FOS,
        ROLES.RETAILER,
        ROLES.SUB_RETAILER,
      ],
    };

    if (role === ROLES.STAFF) {
      if (creatorRole !== ROLES.ADMIN) {
        return res.status(403).json({
          success: false,
          message: "Only Admin can create Staff",
        });
      }

      if (selectedParentId !== null) {
        const selectedParent = await findUserById(
          selectedParentId
        );

        if (!selectedParent) {
          return res.status(404).json({
            success: false,
            message: "Selected parent user not found",
          });
        }

        if (Number(selectedParent.role_id) !== ROLES.ADMIN) {
          return res.status(403).json({
            success: false,
            message: "Staff parent must be an Admin",
          });
        }
      } else {
        selectedParentId = created_by;
      }
    } else {
      if (
        creatorRole === ROLES.EMPLOYEE ||
        creatorRole === ROLES.STAFF
      ) {
        return res.status(403).json({
          success: false,
          message:
            "You do not have permission to create users",
        });
      }

      if (
        creatorRole !== ROLES.MASTER_ADMIN &&
        role <= creatorRole
      ) {
        return res.status(403).json({
          success: false,
          message: `You cannot create this role. Creator role: ${creatorRole}, Requested role: ${role}`,
        });
      }

      if (selectedParentId !== null) {
        const selectedParent = await findUserById(
          selectedParentId
        );

        if (!selectedParent) {
          return res.status(404).json({
            success: false,
            message: "Selected parent user not found",
          });
        }

        const parentRole = Number(selectedParent.role_id);
        const allowedParents = allowedParentRoles[role] || [];

        if (!allowedParents.includes(parentRole)) {
          return res.status(403).json({
            success: false,
            message: "Selected parent role is invalid",
          });
        }

        if (selectedParentId === created_by && role > creatorRole) {
          selectedParentId = created_by;
        }
      } else if (creatorRole !== ROLES.MASTER_ADMIN) {
        selectedParentId = created_by;
      }
    }

    const existingUser = await findUserByEmail(cleanEmail);

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "Email already exists",
      });
    }

    const existingPhone = await db("users")
      .select("id")
      .where("phone", cleanPhone)
      .first();

    if (existingPhone) {
      return res.status(400).json({
        success: false,
        message: "Phone number already exists",
      });
    }

    const retailerDevices = {
      new_device: 0,
      old_device: 0,
      supreme_device: 0,
      pro_star: 0,
      lite: 0,
      google_tv: 0,
      supreme_lock: 0,
    };

    if (role === ROLES.RETAILER) {
      const deviceFields = {
        new_device,
        old_device,
        supreme_device,
        pro_star,
        lite,
        google_tv,
        supreme_lock,
      };

      for (const [field, value] of Object.entries(deviceFields)) {
        if (
          value === undefined ||
          value === null ||
          value === ""
        ) {
          continue;
        }

        const numericValue = Number(value);

        if (![0, 1].includes(numericValue)) {
          return res.status(400).json({
            success: false,
            message: `${field} must be either 0 or 1`,
          });
        }

        retailerDevices[field] = numericValue;
      }
    }

    const hashPassword = await bcrypt.hash(password, 10);

    const userId = await createUserModel({
      organization_name,
      name: cleanName,
      email: cleanEmail,
      phone: cleanPhone,
      password: hashPassword,
      company_address,
      country,
      state,
      city,
      role_id: role,
      created_by,
      parent_id: selectedParentId,
      new_device: retailerDevices.new_device,
      old_device: retailerDevices.old_device,
      supreme_device: retailerDevices.supreme_device,
      pro_star: retailerDevices.pro_star,
      lite: retailerDevices.lite,
      google_tv: retailerDevices.google_tv,
      supreme_lock: retailerDevices.supreme_lock,
    });

    return res.status(201).json({
      success: true,
      message: "User Registered Successfully",
      data: {
        id: userId,
        organization_name,
        name: cleanName,
        email: cleanEmail,
        phone: cleanPhone,
        role_id: role,
        company_address,
        country,
        state,
        city,
        created_by,
        parent_id: selectedParentId,
        new_device: retailerDevices.new_device,
        old_device: retailerDevices.old_device,
        supreme_device: retailerDevices.supreme_device,
        pro_star: retailerDevices.pro_star,
        lite: retailerDevices.lite,
        google_tv: retailerDevices.google_tv,
        supreme_lock: retailerDevices.supreme_lock,
      },
    });
  } catch (error) {
    console.error("CREATE USER ERROR:", error);

    return res.status(500).json({
      success: false,
      message: error.message || "Internal server error",
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

    return res.status(200).json({
      success: true,
      pagination: {
        currentPage: page,
        totalPages: Math.ceil(result.total / limit),
        limit,
        totalUsers: result.total,
      },
      data: result.users,
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

// ADD MODULE
export const addModule = async (req, res) => {
  try {
    const userRole = Number(req.user?.role_id);

    if (userRole !== 0 && userRole !== 8) {
      return res.status(403).json({
        success: false,
        message: "Only Master Admin and Employee can add modules",
      });
    }

    const { module, sequence } = req.body;

    if (!module || typeof module !== "string") {
      return res.status(400).json({
        success: false,
        message: "Module is required",
      });
    }

    const moduleName = module.trim().toLowerCase();

    if (!moduleName) {
      return res.status(400).json({
        success: false,
        message: "Module name cannot be empty",
      });
    }

    const moduleSequence = Number(sequence);

    if (
      sequence === undefined ||
      sequence === null ||
      sequence === "" ||
      !Number.isInteger(moduleSequence) ||
      moduleSequence < 1
    ) {
      return res.status(400).json({
        success: false,
        message: "Valid sequence number is required. Example: 1, 2, 3",
      });
    }

    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: "PNG module icon is required",
      });
    }

    if (req.file.mimetype !== "image/png") {
      return res.status(400).json({
        success: false,
        message: "Only PNG module icons are allowed",
      });
    }

    const maxIconSize = 20 * 1024;

    if (req.file.size > maxIconSize) {
      return res.status(400).json({
        success: false,
        message: "PNG module icon must not exceed 20 KB",
      });
    }

    const masterAdmin = await db("users")
      .select("id", "modules")
      .where("role_id", 0)
      .first();

    if (!masterAdmin) {
      return res.status(404).json({
        success: false,
        message: "Master Admin not found",
      });
    }

    let modules = [];

    if (masterAdmin.modules) {
      try {
        modules =
          typeof masterAdmin.modules === "string"
            ? JSON.parse(masterAdmin.modules)
            : masterAdmin.modules;
      } catch (error) {
        console.error("Modules JSON Parse Error:", error);
        modules = [];
      }
    }

    if (!Array.isArray(modules)) {
      modules = [];
    }

    modules = modules.map((item, index) => {
      if (typeof item === "string") {
        return {
          name: item,
          icon: null,
          sequence: index + 1,
          status: 1,
        };
      }

      return {
        ...item,
        sequence: Number(item?.sequence) || index + 1,
        status: Number(item?.status) === 0 ? 0 : 1,
      };
    });

    const alreadyExists = modules.some(
      (item) =>
        String(item?.name || "").trim().toLowerCase() === moduleName
    );

    if (alreadyExists) {
      return res.status(409).json({
        success: false,
        message: "Module already exists",
        modules,
      });
    }

    const sequenceExists = modules.some(
      (item) => Number(item?.sequence) === moduleSequence
    );

    if (sequenceExists) {
      return res.status(422).json({
        success: false,
        message: `Sequence ${moduleSequence} is already used`,
        modules,
      });
    }

    const iconPath = `/uploads/modules/${req.file.filename}`;

    const newModule = {
      name: moduleName,
      icon: iconPath,
      sequence: moduleSequence,
      status: 1,
    };

    modules.push(newModule);

    modules.sort(
      (a, b) =>
        Number(a?.sequence ?? 999999) -
        Number(b?.sequence ?? 999999)
    );

    await db("users")
      .where("id", masterAdmin.id)
      .where("role_id", 0)
      .update({
        modules: JSON.stringify(modules),
      });

    return res.status(201).json({
      success: true,
      message: "Module added successfully",
      module: newModule,
      modules,
    });
  } catch (error) {
    console.error("Add Module Error:", error);

    return res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error.message,
    });
  }
};

// GET MODULES
export const getModules = async (req, res) => {
  try {
    const masterAdmin = await db("users")
      .select("id", "modules")
      .where("role_id", 0)
      .first();

    if (!masterAdmin) {
      return res.status(404).json({
        success: false,
        message: "Master Admin not found",
      });
    }

    let modules = [];

    if (masterAdmin.modules) {
      try {
        modules =
          typeof masterAdmin.modules === "string"
            ? JSON.parse(masterAdmin.modules)
            : masterAdmin.modules;
      } catch (error) {
        console.error("MODULES JSON PARSE ERROR:", error);

        return res.status(500).json({
          success: false,
          message: "Invalid modules data",
        });
      }
    }

    if (!Array.isArray(modules)) {
      modules = [];
    }

    modules = modules.map((item, index) => {
      if (typeof item === "string") {
        return {
          name: item,
          icon: null,
          sequence: index + 1,
          status: 1,
        };
      }

      const sequence = Number(item?.sequence);
      const status = Number(item?.status);

      return {
        name: item?.name || "",
        icon: item?.icon || null,
        sequence:
          Number.isInteger(sequence) && sequence > 0
            ? sequence
            : index + 1,
        status: status === 0 ? 0 : 1,
      };
    });

    modules.sort(
      (a, b) =>
        Number(a?.sequence ?? 999999) -
        Number(b?.sequence ?? 999999)
    );

    const activeCount = modules.filter(
      (item) => Number(item?.status) === 1
    ).length;

    const inactiveCount = modules.filter(
      (item) => Number(item?.status) === 0
    ).length;

    return res.status(200).json({
      success: true,
      count: modules.length,
      activeCount,
      inactiveCount,
      modules,
    });
  } catch (error) {
    console.error("GET MODULES ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to get modules",
      error: error?.message,
    });
  }
};

// DELETE MODULES
export const deleteModule = async (req, res) => {
  try {
    const { module } = req.body || {};

    if (!module || typeof module !== "string") {
      return res.status(400).json({
        success: false,
        message: "Module name is required",
      });
    }

    const moduleName = module.trim().toLowerCase();

    if (!moduleName) {
      return res.status(400).json({
        success: false,
        message: "Module name cannot be empty",
      });
    }

    const masterAdmin = await db("users")
      .select("id", "modules")
      .where("role_id", 0)
      .first();

    if (!masterAdmin) {
      return res.status(404).json({
        success: false,
        message: "Master Admin not found",
      });
    }

    let modules = [];

    if (masterAdmin.modules) {
      try {
        modules =
          typeof masterAdmin.modules === "string"
            ? JSON.parse(masterAdmin.modules)
            : masterAdmin.modules;
      } catch (error) {
        console.error("MODULE JSON PARSE ERROR:", error);
        modules = [];
      }
    }

    if (!Array.isArray(modules)) {
      modules = [];
    }

    const getModuleName = (item) => {
      if (typeof item === "object" && item !== null) {
        return String(item?.name || "").trim().toLowerCase();
      }

      return String(item || "").trim().toLowerCase();
    };

    const deletedModule = modules.find(
      (item) => getModuleName(item) === moduleName
    );

    if (!deletedModule) {
      return res.status(404).json({
        success: false,
        message: `Module "${module}" not found`,
      });
    }

    const updatedModules = modules.filter(
      (item) => getModuleName(item) !== moduleName
    );

    await db("users")
      .where("id", masterAdmin.id)
      .where("role_id", 0)
      .update({
        modules: JSON.stringify(updatedModules),
      });

    return res.status(200).json({
      success: true,
      message: `Module "${module}" deleted successfully`,
      deletedModule,
      modules: updatedModules,
    });
  } catch (error) {
    console.error("DELETE MODULE ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to delete module",
      error: error.message,
    });
  }
};

// UPADTE MODULES
export const updateModule = async (req, res) => {
  try {
    const removeUploadedFile = () => {
      if (!req.file) return;

      const filePath = path.join(uploadDir, req.file.filename);

      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
    };

    if (Number(req.user?.role_id) !== 0) {
      removeUploadedFile();

      return res.status(403).json({
        success: false,
        message: "Only Master Admin can update module",
      });
    }

    const {
      oldModule,
      newModule,
      newSequence,
      status,
    } = req.body;

    if (typeof oldModule !== "string" || !oldModule.trim()) {
      removeUploadedFile();

      return res.status(400).json({
        success: false,
        message: "Old module name is required",
      });
    }

    const hasNewModule =
      typeof newModule === "string" && newModule.trim() !== "";

    const hasNewSequence =
      newSequence !== undefined &&
      newSequence !== null &&
      String(newSequence).trim() !== "";

    const hasNewStatus =
      status !== undefined &&
      status !== null &&
      String(status).trim() !== "";

    const hasNewIcon = Boolean(req.file);

    if (
      !hasNewModule &&
      !hasNewSequence &&
      !hasNewStatus &&
      !hasNewIcon
    ) {
      removeUploadedFile();

      return res.status(400).json({
        success: false,
        message: "At least one field is required to update",
      });
    }

    let sequence = null;

    if (hasNewSequence) {
      sequence = Number(newSequence);

      if (!Number.isInteger(sequence) || sequence < 1) {
        removeUploadedFile();

        return res.status(400).json({
          success: false,
          message: "Valid sequence number is required",
        });
      }
    }

    let moduleStatus = null;

    if (hasNewStatus) {
      moduleStatus = Number(status);

      if (moduleStatus !== 0 && moduleStatus !== 1) {
        removeUploadedFile();

        return res.status(400).json({
          success: false,
          message: "Status must be either 0 or 1",
        });
      }
    }

    const oldModuleName = oldModule.trim().toLowerCase();

    const newModuleName = hasNewModule
      ? newModule.trim().toLowerCase()
      : null;

    const masterAdmin = await db("users")
      .select("id", "modules")
      .where("role_id", 0)
      .first();

    if (!masterAdmin) {
      removeUploadedFile();

      return res.status(404).json({
        success: false,
        message: "Master Admin not found",
      });
    }

    let modules = masterAdmin.modules;

    if (!modules) {
      modules = [];
    } else if (typeof modules === "string") {
      try {
        modules = JSON.parse(modules);
      } catch (error) {
        removeUploadedFile();

        return res.status(500).json({
          success: false,
          message: "Invalid modules data",
        });
      }
    }

    if (!Array.isArray(modules)) {
      removeUploadedFile();

      return res.status(500).json({
        success: false,
        message: "Modules data must be an array",
      });
    }

    modules = modules.map((item, index) => {
      if (typeof item === "string") {
        return {
          name: item,
          icon: null,
          sequence: index + 1,
          status: 1,
        };
      }

      return {
        name: item?.name || "",
        icon: item?.icon || null,
        sequence: Number(item?.sequence ?? index + 1),
        status: Number(item?.status ?? 1) === 0 ? 0 : 1,
      };
    });

    const moduleIndex = modules.findIndex(
      (item) =>
        String(item?.name || "").trim().toLowerCase() === oldModuleName
    );

    if (moduleIndex === -1) {
      removeUploadedFile();

      return res.status(404).json({
        success: false,
        message: `Old module "${oldModule}" not found`,
      });
    }

    const currentModule = modules[moduleIndex];

    if (hasNewModule) {
      const duplicateModule = modules.some(
        (item, index) =>
          index !== moduleIndex &&
          String(item?.name || "").trim().toLowerCase() === newModuleName
      );

      if (duplicateModule) {
        removeUploadedFile();

        return res.status(409).json({
          success: false,
          message: `Module "${newModule}" already exists`,
        });
      }
    }

    if (hasNewSequence) {
      const duplicateSequence = modules.some(
        (item, index) =>
          index !== moduleIndex &&
          Number(item?.sequence) === sequence
      );

      if (duplicateSequence) {
        removeUploadedFile();

        return res.status(422).json({
          success: false,
          message: `Sequence ${sequence} is already used`,
        });
      }
    }

    const oldIcon = currentModule?.icon || null;

    const finalName = hasNewModule
      ? newModuleName
      : currentModule?.name || "";

    const finalSequence = hasNewSequence
      ? sequence
      : Number(currentModule?.sequence || moduleIndex + 1);

    const finalStatus = hasNewStatus
      ? moduleStatus
      : Number(currentModule?.status ?? 1) === 0
        ? 0
        : 1;

    const finalIcon = hasNewIcon
      ? `/uploads/modules/${req.file.filename}`
      : currentModule?.icon || null;

    const previousStatus = Number(currentModule?.status ?? 1);

    modules[moduleIndex] = {
      name: finalName,
      icon: finalIcon,
      sequence: finalSequence,
      status: finalStatus,
    };

    modules.sort(
      (a, b) =>
        Number(a?.sequence ?? 999999) -
        Number(b?.sequence ?? 999999)
    );

    if (
      hasNewStatus &&
      previousStatus === 1 &&
      finalStatus === 0
    ) {
      const roleMap = {
        admin: 1,
        cnf: 2,
        "super distributor": 3,
        "super distributer": 3,
        distributor: 4,
        fos: 5,
        retailer: 6,
        "sub retailer": 7,
        employee: 8,
        staff: 9,
      };

      const inactiveRoleId = roleMap[oldModuleName];

      if (inactiveRoleId) {
        const inactiveUsers = await db("users")
          .select("id", "parent_id")
          .where("role_id", inactiveRoleId);

        for (const inactiveUser of inactiveUsers) {
          if (!inactiveUser.parent_id) {
            continue;
          }

          await db("users")
            .where("parent_id", inactiveUser.id)
            .update({
              parent_id: inactiveUser.parent_id,
            });
        }
      }
    }

    await db("users")
      .where("id", masterAdmin.id)
      .where("role_id", 0)
      .update({
        modules: JSON.stringify(modules),
      });

    if (hasNewIcon && oldIcon && oldIcon !== finalIcon) {
      try {
        const oldIconPath = path.join(
          process.cwd(),
          oldIcon.replace(/^\/+/, "")
        );

        if (fs.existsSync(oldIconPath)) {
          fs.unlinkSync(oldIconPath);
        }
      } catch (iconDeleteError) {
        console.error(
          "OLD ICON DELETE ERROR:",
          iconDeleteError
        );
      }
    }

    return res.status(200).json({
      success: true,
      message: "Module updated successfully",
      module: {
        oldModule: oldModuleName,
        newModule: finalName,
        icon: finalIcon,
        sequence: finalSequence,
        status: finalStatus,
      },
      modules,
    });
  } catch (error) {
    console.error("UPDATE MODULE ERROR:", error);

    if (req.file) {
      try {
        const filePath = path.join(uploadDir, req.file.filename);

        if (fs.existsSync(filePath)) {
          fs.unlinkSync(filePath);
        }
      } catch (fileError) {
        console.error("FILE DELETE ERROR:", fileError);
      }
    }

    return res.status(500).json({
      success: false,
      message: error?.message || "Failed to update module",
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