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




// import {
//   findUserByEmail,
//   findUserById,
//   createUser as createUserModel,
// } from "../models/userModel.js";

// import {
//   ROLES,
//   isValidRole,
// } from "../constants/roles.js";


export const createuserrole = async (req, res) => {
  try {
    // =====================================================
    // REQUEST BODY
    // =====================================================

    const {
      organization_name,
      role_id,
      name,
      email,
      phone,
      password,
      confirm_password,
      company_address,
      country,
      state,
      city,

      // DEVICE PERMISSIONS
      new_device,
      old_device,
      supreme_device,
      pro_star,
      lite,
      google_tv,
      supreme_lock,
    } = req.body;

    // =====================================================
    // BASIC VALIDATION
    // =====================================================

    if (!name || !name.trim()) {
      return res.status(400).json({
        success: false,
        message: "Name is required",
      });
    }

    if (!email || !email.trim()) {
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

    if (!confirm_password) {
      return res.status(400).json({
        success: false,
        message: "Confirm Password is required",
      });
    }

    // =====================================================
    // CLEAN DATA
    // =====================================================

    const cleanName = name.trim();
    const cleanEmail = email.trim().toLowerCase();

    // =====================================================
    // PASSWORD MATCH
    // =====================================================

    if (password !== confirm_password) {
      return res.status(400).json({
        success: false,
        message: "Password and Confirm Password not match",
      });
    }

    // =====================================================
    // ROLE
    // =====================================================

    const role = Number(role_id);

    if (!isValidRole(role)) {
      return res.status(400).json({
        success: false,
        message: "Invalid role_id",
      });
    }

    // =====================================================
    // MASTER ADMIN CANNOT BE CREATED
    // =====================================================

    if (role === ROLES.MASTER_ADMIN) {
      return res.status(403).json({
        success: false,
        message: "Master Admin cannot be created",
      });
    }

    // =====================================================
    // LOGGED-IN USER
    // =====================================================

    if (!req.user || !req.user.id) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized",
      });
    }

    const created_by = Number(req.user.id);

    // =====================================================
    // FIND CREATOR
    // =====================================================

    const creator = await findUserById(created_by);

    if (!creator) {
      return res.status(404).json({
        success: false,
        message: "Creator not found",
      });
    }

    const creatorRole = Number(creator.role_id);

    // =====================================================
    // ROLE CREATION PERMISSION
    // =====================================================
    //
    // Higher role can create ANY lower role.
    //
    // Example:
    //
    // Admin 1
    //   -> CNF 2
    //   -> Super Distributor 3
    //   -> Distributor 4
    //   -> FOS 5
    //   -> Retailer 6
    //   -> Sub Retailer 7
    //   -> Employee 8
    //   -> Staff 9 ONLY
    //
    // CNF 2
    //   -> Super Distributor 3
    //   -> Distributor 4
    //   -> FOS 5
    //   -> Retailer 6
    //   -> Sub Retailer 7
    //   -> Employee 8
    //
    // Distributor 4
    //   -> FOS 5
    //   -> Retailer 6
    //   -> Sub Retailer 7
    //   -> Employee 8
    //
    // Retailer 6
    //   -> Sub Retailer 7
    //   -> Employee 8
    //
    // =====================================================

    // -----------------------------------------------------
    // STAFF
    // -----------------------------------------------------
    //
    // Staff sirf Admin create kar sakta hai.
    //
    if (role === ROLES.STAFF) {
      if (creatorRole !== ROLES.ADMIN) {
        return res.status(403).json({
          success: false,
          message: "Only Admin can create Staff",
        });
      }
    }

    // -----------------------------------------------------
    // NORMAL ROLES
    // -----------------------------------------------------
    else {
      // Employee aur Staff se koi normal role create nahi hoga
      if (
        creatorRole === ROLES.EMPLOYEE ||
        creatorRole === ROLES.STAFF
      ) {
        return res.status(403).json({
          success: false,
          message: "You do not have permission to create users",
        });
      }

      // Master Admin can create any normal role
      if (creatorRole === ROLES.MASTER_ADMIN) {
        // Allowed
      }

      // Higher role can create any lower role
      else if (role <= creatorRole) {
        return res.status(403).json({
          success: false,
          message:
            `You cannot create this role. Creator role: ${creatorRole}, Requested role: ${role}`,
        });
      }
    }

    // =====================================================
    // EMAIL CHECK
    // =====================================================

    const existingUser = await findUserByEmail(cleanEmail);

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "Email already exists",
      });
    }

    // =====================================================
    // DEVICE PERMISSIONS
    // =====================================================
    //
    // IMPORTANT:
    //
    // Device permissions ONLY Retailer ke liye hain.
    //
    // Retailer:
    // role_id = 6
    //
    // Baaki roles:
    // device values automatically 0 save hongi.
    //
    // =====================================================

    let retailerDevices = {
      new_device: 0,
      old_device: 0,
      supreme_device: 0,
      pro_star: 0,
      lite: 0,
      google_tv: 0,
      supreme_lock: 0,
    };

    // =====================================================
    // RETAILER DEVICE VALIDATION
    // =====================================================

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
        // Agar value nahi bheji gayi
        // toh 0 save hoga

        if (
          value === undefined ||
          value === null ||
          value === ""
        ) {
          retailerDevices[field] = 0;
          continue;
        }

        const numericValue = Number(value);

        // Only 0 or 1
        if (![0, 1].includes(numericValue)) {
          return res.status(400).json({
            success: false,
            message: `${field} must be either 0 or 1`,
          });
        }

        retailerDevices[field] = numericValue;
      }
    }

    // =====================================================
    // HASH PASSWORD
    // =====================================================

    const hashPassword = await bcrypt.hash(password, 10);

    // =====================================================
    // PARENT ID
    // =====================================================

    // Jis user ne create kiya
    // uski ID parent_id hogi.

    const parent_id = created_by;

    // =====================================================
    // CREATE USER
    // =====================================================

    const userId = await createUserModel({
      // ===================================================
      // BASIC DETAILS
      // ===================================================

      organization_name,

      name: cleanName,

      email: cleanEmail,

      phone,

      password: hashPassword,

      company_address,

      country,

      state,

      city,

      // ===================================================
      // ROLE
      // ===================================================

      role_id: role,

      // ===================================================
      // CREATOR
      // ===================================================

      created_by,

      // ===================================================
      // PARENT
      // ===================================================

      parent_id,

      // ===================================================
      // DEVICE PERMISSIONS
      //
      // Sirf Retailer ke liye actual values.
      // Baaki sab ke liye 0.
      // ===================================================

      new_device: retailerDevices.new_device,

      old_device: retailerDevices.old_device,

      supreme_device: retailerDevices.supreme_device,

      pro_star: retailerDevices.pro_star,

      lite: retailerDevices.lite,

      google_tv: retailerDevices.google_tv,

      supreme_lock: retailerDevices.supreme_lock,
    });

    // =====================================================
    // SUCCESS RESPONSE
    // =====================================================

    return res.status(201).json({
      success: true,

      message: "User Registered Successfully",

      data: {
        // =================================================
        // USER
        // =================================================

        id: userId,

        organization_name,

        name: cleanName,

        email: cleanEmail,

        phone,

        role_id: role,

        company_address,

        country,

        state,

        city,

        // =================================================
        // CREATOR
        // =================================================

        created_by,

        // =================================================
        // PARENT
        // =================================================

        parent_id,

        // =================================================
        // DEVICE PERMISSIONS
        // =================================================

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
    console.error("Create User Error:", error);

    return res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};
// =========================
// Login staff
// =========================
export const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    // ==========================================
    // FIND USER
    // ==========================================

    const user = await findUserByEmail(email);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // ==========================================
    // CHECK PASSWORD
    // ==========================================

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(401).json({
        success: false,
        message: "Invalid password",
      });
    }

    // ==========================================
    // JWT TOKEN
    // Only required information in token
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
    // RESPONSE
    // Parent IDs are NOT inside JWT.
    // They are sent separately in user object.
    // Frontend can store them in localStorage.
    // ==========================================

    return res.status(200).json({
      success: true,
      message: "Login Successful",

      token,

      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role_id: user.role_id,

        // ======================================
        // HIERARCHY DATA
        // NOT PART OF JWT
        // ======================================

        parent_id: user.parent_id,
        parent_admin_id: user.parent_admin_id,
        parent_cnf_id: user.parent_cnf_id,
        parent_super_distributor_id:
          user.parent_super_distributor_id,
        parent_distributor_id:
          user.parent_distributor_id,
        parent_fos_id: user.parent_fos_id,
        parent_retailer_id: user.parent_retailer_id,
        parent_employee_id: user.parent_employee_id,
        parent_staff_id: user.parent_staff_id,
      },
    });
  } catch (error) {
    console.error("Login Error:", error);

    return res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

// =========================
// GET ALL USERS
// =========================
export const getUsers = async (req, res) => {
  try {

    // ==========================================
    // PAGINATION
    // ==========================================

    const page =
      Number(req.query.page) || 1;

    const limit =
      Number(req.query.limit) || 10;

    const offset =
      (page - 1) * limit;


    // ==========================================
    // OPTIONAL ROLE FILTER
    // ==========================================

    const role_id =
      req.query.role_id !== undefined &&
      req.query.role_id !== ""
        ? Number(req.query.role_id)
        : null;


    // ==========================================
    // GET USERS
    // ==========================================

    const result =
      await getAllUsers(
        limit,
        offset,
        role_id
      );


    // ==========================================
    // RESPONSE
    // ==========================================

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

      data: result.users,

    });

  } catch (error) {

    console.error(
      "Get Users Error:",
      error
    );

    return res.status(500).json({

      success: false,

      message: error.message,

    });

  }
};

// =========================
// Logout api
// =========================
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

// =========================
// User Chain Api
// =========================
export const getDropdownUsers = async (req, res) => {
  try {
    const { role_id, parent_id } = req.query;

    // =====================================================
    // VALIDATE ROLE ID
    // =====================================================

    if (!role_id) {
      return res.status(400).json({
        success: false,
        message: "role_id is required",
      });
    }

    const createRoleId = Number(role_id);

    if (Number.isNaN(createRoleId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid role_id",
      });
    }

    // =====================================================
    // ROLE HIERARCHY
    //
    // 1 = Admin
    // 2 = CNF
    // 3 = Super Distributor
    // 4 = Distributor
    // 5 = FOS
    // 6 = Retailer
    // 7 = Sub Retailer
    // 8 = Employee
    // 9 = Staff
    // =====================================================

    const hierarchy = {
      2: [1, 2],
      3: [2, 3],
      4: [2, 3, 4],
      5: [2, 3, 4, 5],
      6: [2, 3, 4, 5, 6],
      7: [2, 3, 4, 5, 6, 7],
      8: [2, 3, 4, 5, 6, 7, 8],
      9: [2, 3, 4, 5, 6, 7, 8, 9],
    };

    // =====================================================
    // CHECK ROLE
    // =====================================================

    if (!hierarchy[createRoleId]) {
      return res.status(400).json({
        success: false,
        message: "Invalid or unsupported role_id",
      });
    }

    // =====================================================
    // VALIDATE PARENT ID
    // =====================================================

    let selectedParentId = null;

    if (
      parent_id !== undefined &&
      parent_id !== null &&
      parent_id !== ""
    ) {
      selectedParentId = Number(parent_id);

      if (Number.isNaN(selectedParentId)) {
        return res.status(400).json({
          success: false,
          message: "Invalid parent_id",
        });
      }
    }

    // =====================================================
    // CASE 1
    //
    // NO PARENT
    //
    // Example:
    //
    // role_id = 4
    //
    // Return first parent = CNF
    // =====================================================

    if (selectedParentId === null) {
      const firstParentRole =
        hierarchy[createRoleId][0];

      const [rows] = await db.query(
        `
          SELECT
            id,
            name,
            email,
            phone,
            role_id,
            parent_id,
            created_by
          FROM users
          WHERE role_id = ?
          ORDER BY name ASC
        `,
        [firstParentRole]
      );

      console.log(
        "=========================================="
      );

      console.log(
        "HIERARCHY DROPDOWN - FIRST LEVEL"
      );

      console.log(
        "Create Role:",
        createRoleId
      );

      console.log(
        "Fetch Role:",
        firstParentRole
      );

      console.log(
        "Total:",
        rows.length
      );

      console.log(
        "=========================================="
      );

      return res.status(200).json({
        success: true,

        create_role_id:
          createRoleId,

        parent_id:
          null,

        current_role_id:
          firstParentRole,

        current_role_name:
          getRoleName(firstParentRole),

        total:
          rows.length,

        data:
          rows,
      });
    }

    // =====================================================
    // CASE 2
    //
    // PARENT SELECTED
    // =====================================================

    const [parentRows] = await db.query(
      `
        SELECT
          id,
          name,
          role_id,
          parent_id
        FROM users
        WHERE id = ?
        LIMIT 1
      `,
      [selectedParentId]
    );

    // =====================================================
    // PARENT NOT FOUND
    // =====================================================

    if (!parentRows.length) {
      return res.status(404).json({
        success: false,
        message: "Parent user not found",
      });
    }

    const parentRoleId =
      Number(parentRows[0].role_id);

    // =====================================================
    // CREATE ROLE HIERARCHY
    // =====================================================

    const levels =
      hierarchy[createRoleId];

    const parentIndex =
      levels.indexOf(parentRoleId);

    // =====================================================
    // INVALID PARENT
    // =====================================================

    if (parentIndex === -1) {
      return res.status(400).json({
        success: false,

        message:
          "Selected parent is not valid for this role hierarchy",

        create_role_id:
          createRoleId,

        selected_parent_id:
          selectedParentId,

        selected_parent_role_id:
          parentRoleId,

        allowed_parent_roles:
          levels,
      });
    }

    // =====================================================
    // NEXT ROLE
    // =====================================================

    const nextRoleIndex =
      parentIndex + 1;

    // =====================================================
    // NO NEXT ROLE
    // =====================================================

    if (
      nextRoleIndex >=
      levels.length
    ) {
      return res.status(200).json({
        success: true,

        create_role_id:
          createRoleId,

        parent_id:
          selectedParentId,

        current_role_id:
          null,

        current_role_name:
          null,

        total:
          0,

        data: [],

        message:
          "Hierarchy completed",
      });
    }

    const fetchRoleId =
      levels[nextRoleIndex];

    // =====================================================
    // FETCH CHILD USERS
    // =====================================================

    const [rows] = await db.query(
      `
        SELECT
          id,
          name,
          email,
          phone,
          role_id,
          parent_id,
          created_by
        FROM users
        WHERE role_id = ?
        AND parent_id = ?
        ORDER BY name ASC
      `,
      [
        fetchRoleId,
        selectedParentId,
      ]
    );

    // =====================================================
    // DEBUG
    // =====================================================

    console.log(
      "=========================================="
    );

    console.log(
      "HIERARCHY DROPDOWN"
    );

    console.log(
      "Create Role:",
      createRoleId
    );

    console.log(
      "Hierarchy:",
      levels
    );

    console.log(
      "Selected Parent:",
      selectedParentId
    );

    console.log(
      "Parent Role:",
      parentRoleId
    );

    console.log(
      "Next Role:",
      fetchRoleId
    );

    console.log(
      "Total:",
      rows.length
    );

    console.log(
      "=========================================="
    );

    // =====================================================
    // RESPONSE
    // =====================================================

    return res.status(200).json({
      success: true,

      create_role_id:
        createRoleId,

      parent_id:
        selectedParentId,

      parent_role_id:
        parentRoleId,

      current_role_id:
        fetchRoleId,

      current_role_name:
        getRoleName(fetchRoleId),

      total:
        rows.length,

      data:
        rows,
    });

  } catch (error) {

    console.error(
      "getDropdownUsers Error:",
      error
    );

    return res.status(500).json({
      success: false,

      message:
        "Failed to get dropdown users",

      error:
        error.message,
    });
  }
};


// =====================================================
// ROLE NAME
// =====================================================

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


export const updatedstaffdata = async (req, res) => {
  try {
    const { id } = req.params;

    const {
      organization_name,
      name,
      email,
      phone,
      company_address,
      country,
      state,
      city,

      parent_admin_id,
      parent_cnf_id,
      parent_super_distributor_id,
      parent_distributor_id,
      parent_fos_id,
      parent_retailer_id,

      new_device,
      old_device,
      supreme_device,
      pro_star,
      lite,
      google_tv,
      supreme_lock,
    } = req.body;

    if (!id) {
      return res.status(400).json({
        success: false,
        message: "User ID is required",
      });
    }

    // Check user exists
    const [existingUser] = await db.query(
      "SELECT id FROM users WHERE id = ?",
      [id]
    );

    if (existingUser.length === 0) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // Update according to ID
    const [result] = await db.query(
      `
      UPDATE users
      SET
        organization_name = ?,
        name = ?,
        email = ?,
        phone = ?,
        company_address = ?,
        country = ?,
        state = ?,
        city = ?,

        parent_admin_id = ?,
        parent_cnf_id = ?,
        parent_super_distributor_id = ?,
        parent_distributor_id = ?,
        parent_fos_id = ?,
        parent_retailer_id = ?,

        new_device = ?,
        old_device = ?,
        supreme_device = ?,
        pro_star = ?,
        lite = ?,
        google_tv = ?,
        supreme_lock = ?

      WHERE id = ?
      `,
      [
        organization_name,
        name,
        email,
        phone,
        company_address,
        country,
        state,
        city,

        parent_admin_id || null,
        parent_cnf_id || null,
        parent_super_distributor_id || null,
        parent_distributor_id || null,
        parent_fos_id || null,
        parent_retailer_id || null,

        new_device ?? 0,
        old_device ?? 0,
        supreme_device ?? 0,
        pro_star ?? 0,
        lite ?? 0,
        google_tv ?? 0,
        supreme_lock ?? 0,

        id,
      ]
    );

    if (result.affectedRows === 0) {
      return res.status(400).json({
        success: false,
        message: "No changes made",
      });
    }

    // Get updated user data
    const [updatedUser] = await db.query(
      `
      SELECT
        id,
        organization_name,
        name,
        email,
        phone,
        company_address,
        country,
        state,
        city,
        role_id,

        parent_admin_id,
        parent_cnf_id,
        parent_super_distributor_id,
        parent_distributor_id,
        parent_fos_id,
        parent_retailer_id,

        new_device,
        old_device,
        supreme_device,
        pro_star,
        lite,
        google_tv,
        supreme_lock
      FROM users
      WHERE id = ?
      `,
      [id]
    );

    return res.status(200).json({
      success: true,
      message: "Staff data updated successfully",
      data: updatedUser[0],
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

    if (!Number.isInteger(userId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid User ID",
      });
    }

    const [rows] = await db.query(
      `
      SELECT
        id,
        organization_name,
        role_id,
        name,
        email,
        phone,
        password,
        company_address,
        country,
        state,
        city,

        parent_admin_id,
        parent_cnf_id,
        parent_super_distributor_id,
        parent_distributor_id,
        parent_fos_id,
        parent_retailer_id,
        parent_staff_id,

        new_device,
        old_device,
        supreme_device,
        pro_star,
        lite,
        google_tv,
        supreme_lock

      FROM users
      WHERE id = ?
      LIMIT 1
      `,
      [userId]
    );

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    return res.status(200).json({
      success: true,
      data: rows[0],
    });

  } catch (error) {
    console.error("Get Staff Data Error:", error);

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

    // ==========================================
    // CURRENT LOGGED-IN USER
    // ==========================================

    const loggedInUser = req.user;

    // ==========================================
    // TARGET USER ID
    // ==========================================

    const { user_id } = req.body;

    if (!user_id) {
      return res.status(400).json({
        success: false,
        message: "User ID is required",
      });
    }

    // ==========================================
    // FIND TARGET USER
    // ==========================================

    const targetUser =
      await findUserById(user_id);

    if (!targetUser) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // ==========================================
    // SAME USER CHECK
    // ==========================================

    if (
      Number(loggedInUser.id) ===
      Number(targetUser.id)
    ) {
      return res.status(400).json({
        success: false,
        message:
          "You are already logged in as this user",
      });
    }

    // ==========================================
    // ORIGINAL ROLE
    // ==========================================
    //
    // Normal login:
    //
    // Distributor = 4
    //
    // Impersonation:
    //
    // Distributor -> FOS
    //
    // Current role = 5
    // Original role = 4
    //
    // Permission hamesha ORIGINAL ROLE
    // se calculate hogi.
    // ==========================================

    const originalRoleId =
      loggedInUser.is_impersonating &&
      loggedInUser.original_role_id !== null &&
      loggedInUser.original_role_id !== undefined
        ? Number(
            loggedInUser.original_role_id
          )
        : Number(
            loggedInUser.role_id
          );

    const originalUserId =
      loggedInUser.is_impersonating &&
      loggedInUser.original_user_id
        ? Number(
            loggedInUser.original_user_id
          )
        : Number(
            loggedInUser.id
          );

    // ==========================================
    // ROLE HIERARCHY
    //
    // 0 Master Admin
    // 1 Admin
    // 2 CNF
    // 3 Super Distributor
    // 4 Distributor
    // 5 FOS
    // 6 Retailer
    // 7 Employee
    // 8 Staff
    // ==========================================

    // Target lower-level role hona chahiye
    // ORIGINAL LOGIN USER ke comparison mein.
    //
    // Example:
    //
    // Distributor (4)
    //     ↓
    // FOS (5)       ALLOWED
    //
    // FOS (5)
    //     ↓
    // Distributor (4)  BLOCKED
    //
    // But agar Distributor -> FOS hua hai,
    // originalRoleId abhi bhi 4 hai.
    //
    // Isliye:
    //
    // Distributor -> FOS -> Distributor
    // ALLOWED
    //

    if (
      Number(targetUser.role_id) <=
      Number(originalRoleId)
    ) {

      // IMPORTANT:
      // Agar target original user khud hai,
      // toh usko wapas login karne dena hai.

      if (
        Number(targetUser.id) !==
        Number(originalUserId)
      ) {
        return res.status(403).json({
          success: false,
          message:
            "You can only login as a lower level user",
        });
      }
    }

    // ==========================================
    // CREATE TARGET USER TOKEN
    // ==========================================

    const token = jwt.sign(
      {
        // CURRENT USER
        id: targetUser.id,

        role_id:
          Number(targetUser.role_id),

        email: targetUser.email,

        // ======================================
        // ORIGINAL LOGIN USER
        // ======================================

        original_user_id:
          originalUserId,

        original_role_id:
          originalRoleId,

        // ======================================
        // IMPERSONATION
        // ======================================

        is_impersonating: true,
      },

      process.env.JWT_SECRET,

      {
        expiresIn: "7d",
      }
    );

    // ==========================================
    // RESPONSE
    // ==========================================

    return res.status(200).json({

      success: true,

      message:
        "Login as user successful",

      token,

      user: {

        id: targetUser.id,

        name: targetUser.name,

        email: targetUser.email,

        role_id:
          Number(targetUser.role_id),

        parent_id:
          targetUser.parent_id || null,

        parent_admin_id:
          targetUser.parent_admin_id || null,

        parent_cnf_id:
          targetUser.parent_cnf_id || null,

        parent_super_distributor_id:
          targetUser.parent_super_distributor_id ||
          null,

        parent_distributor_id:
          targetUser.parent_distributor_id ||
          null,

        parent_fos_id:
          targetUser.parent_fos_id ||
          null,

        parent_retailer_id:
          targetUser.parent_retailer_id ||
          null,

        parent_employee_id:
          targetUser.parent_employee_id ||
          null,

        parent_staff_id:
          targetUser.parent_staff_id ||
          null,
      },
    });

  } catch (error) {

    console.error(
      "Login As User Error:",
      error
    );

    return res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};


// =====================================================
// SIDEMENU MODULE
// =====================================================
export const addModule = async (req, res) => {
  try {
    // ==========================================
    // ONLY MASTER ADMIN
    // ==========================================

    if (Number(req.user?.role_id) !== 0) {
      return res.status(403).json({
        success: false,
        message: "Only Master Admin can add modules",
      });
    }

    const { module } = req.body;

    // ==========================================
    // VALIDATION
    // ==========================================

    if (!module || typeof module !== "string") {
      return res.status(400).json({
        success: false,
        message: "Module is required",
      });
    }

    const moduleName = module.trim().toLowerCase();

    // ==========================================
    // GET MASTER ADMIN
    // ==========================================

    const [rows] = await db.query(
      `
      SELECT id, modules
      FROM users
      WHERE role_id = 0
      LIMIT 1
      `
    );

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        message: "Master Admin not found",
      });
    }

    const masterAdmin = rows[0];

    // ==========================================
    // GET EXISTING MODULES
    // ==========================================

    let modules = [];

    if (masterAdmin.modules) {
      modules =
        typeof masterAdmin.modules === "string"
          ? JSON.parse(masterAdmin.modules)
          : masterAdmin.modules;
    }

    // Safety check
    if (!Array.isArray(modules)) {
      modules = [];
    }

    // ==========================================
    // DUPLICATE CHECK
    // ==========================================

    if (modules.includes(moduleName)) {
      return res.status(409).json({
        success: false,
        message: "Module already exists",
        modules,
      });
    }

    // ==========================================
    // ADD MODULE
    // ==========================================

    modules.push(moduleName);

    // ==========================================
    // UPDATE MASTER ADMIN
    // ==========================================

    await db.query(
      `
      UPDATE users
      SET modules = ?
      WHERE id = ?
      `,
      [
        JSON.stringify(modules),
        masterAdmin.id,
      ]
    );

    // ==========================================
    // RESPONSE
    // ==========================================

    return res.status(201).json({
      success: true,
      message: "Module added successfully",
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

export const getModules = async (req, res) => {
  try {
    // ==========================================
    // GET MASTER ADMIN MODULES
    // ==========================================

    const [rows] = await db.query(
      `
      SELECT modules
      FROM users
      WHERE role_id = 0
      LIMIT 1
      `
    );

    // ==========================================
    // MASTER ADMIN NOT FOUND
    // ==========================================

    if (!rows.length) {
      return res.json({
        success: true,
        modules: [],
      });
    }

    // ==========================================
    // GET MODULES
    // ==========================================

    let modules = [];

    if (rows[0].modules) {
      modules =
        typeof rows[0].modules === "string"
          ? JSON.parse(rows[0].modules)
          : rows[0].modules;
    }

    // ==========================================
    // SAFETY CHECK
    // ==========================================

    if (!Array.isArray(modules)) {
      modules = [];
    }

    // ==========================================
    // RESPONSE
    // ==========================================

    return res.json({
      success: true,
      modules,
    });

  } catch (error) {
    console.error("Get Modules Error:", error);

    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

export const deleteModule = async (req, res) => {
  try {

    console.log(
      "DELETE MODULE BODY:",
      req.body
    );

    const { module } = req.body || {};

    if (!module) {
      return res.status(400).json({
        success: false,
        message: "Module name is required",
      });
    }

    const moduleName =
      String(module).trim();

    // ==========================================
    // GET MASTER ADMIN
    // ==========================================

    const [rows] = await db.query(
      `
      SELECT modules
      FROM users
      WHERE role_id = 0
      LIMIT 1
      `
    );

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        message: "Master Admin not found",
      });
    }

    // ==========================================
    // GET MODULE ARRAY
    // ==========================================

    let modules = [];

    if (rows[0].modules) {

      modules =
        typeof rows[0].modules === "string"
          ? JSON.parse(rows[0].modules)
          : rows[0].modules;

    }

    if (!Array.isArray(modules)) {
      modules = [];
    }

    console.log(
      "OLD MODULES:",
      modules
    );

    // ==========================================
    // FIND MODULE
    // ==========================================

    const moduleExists =
      modules.some(
        (item) =>
          String(item)
            .trim()
            .toLowerCase() ===
          moduleName.toLowerCase()
      );

    if (!moduleExists) {

      return res.status(404).json({
        success: false,
        message: `Module "${moduleName}" not found`,
      });

    }

    // ==========================================
    // DELETE MODULE
    // ==========================================

    const updatedModules =
      modules.filter(
        (item) =>
          String(item)
            .trim()
            .toLowerCase() !==
          moduleName.toLowerCase()
      );

    console.log(
      "UPDATED MODULES:",
      updatedModules
    );

    // ==========================================
    // UPDATE DATABASE
    // ==========================================

    const [result] = await db.query(
      `
      UPDATE users
      SET modules = ?
      WHERE role_id = 0
      `,
      [
        JSON.stringify(
          updatedModules
        ),
      ]
    );

    console.log(
      "UPDATE RESULT:",
      result
    );

    // ==========================================
    // SUCCESS
    // ==========================================

    return res.status(200).json({
      success: true,
      message: "Module deleted successfully",
      modules: updatedModules,
    });

  } catch (error) {

    console.error(
      "Delete Module Error:",
      error
    );

    return res.status(500).json({
      success: false,
      message: "Failed to delete module",
      error: error.message,
    });

  }
};


export const updateModule = async (req, res) => {
  try {

    // =================================================
    // ROLE CHECK
    // =================================================

    if (Number(req.user?.role_id) !== 0) {

      return res.status(403).json({
        success: false,
        message:
          "Only Master Admin can update module",
      });

    }

    // =================================================
    // GET DATA
    // =================================================

    const {
      oldModule,
      newModule,
    } = req.body;

    // =================================================
    // VALIDATION
    // =================================================

    if (
      typeof oldModule !== "string" ||
      !oldModule.trim()
    ) {

      return res.status(400).json({
        success: false,
        message:
          "Old module name is required",
      });

    }

    if (
      typeof newModule !== "string" ||
      !newModule.trim()
    ) {

      return res.status(400).json({
        success: false,
        message:
          "New module name is required",
      });

    }

    const oldName =
      oldModule.trim();

    const newName =
      newModule.trim();

    // =================================================
    // GET MASTER ADMIN MODULES
    // =================================================

    const [rows] = await db.query(
      `
      SELECT modules
      FROM users
      WHERE role_id = 0
      LIMIT 1
      `
    );

    if (!rows.length) {

      return res.status(404).json({
        success: false,
        message:
          "Master Admin not found",
      });

    }

    // =================================================
    // PARSE MODULES
    // =================================================

    let modules =
      rows[0].modules;

    if (!modules) {

      modules = [];

    } else if (
      typeof modules === "string"
    ) {

      try {

        modules =
          JSON.parse(modules);

      } catch (error) {

        modules = [];

      }

    }

    if (!Array.isArray(modules)) {

      modules = [];

    }

    // =================================================
    // FIND OLD MODULE
    // =================================================

    const moduleIndex =
      modules.findIndex(
        (item) =>
          String(item)
            .trim()
            .toLowerCase() ===
          oldName.toLowerCase()
      );

    if (moduleIndex === -1) {

      return res.status(404).json({
        success: false,
        message:
          "Module not found",
      });

    }

    // =================================================
    // DUPLICATE NEW MODULE CHECK
    // =================================================

    const duplicate =
      modules.some(
        (item, index) =>
          index !== moduleIndex &&
          String(item)
            .trim()
            .toLowerCase() ===
          newName.toLowerCase()
      );

    if (duplicate) {

      return res.status(409).json({
        success: false,
        message:
          "Module already exists",
      });

    }

    // =================================================
    // UPDATE MODULE
    // =================================================

    modules[moduleIndex] =
      newName;

    // =================================================
    // UPDATE DATABASE
    // =================================================

    await db.query(
      `
      UPDATE users
      SET modules = ?
      WHERE role_id = 0
      `,
      [
        JSON.stringify(modules)
      ]
    );

    // =================================================
    // RESPONSE
    // =================================================

    return res.status(200).json({
      success: true,
      message:
        "Module updated successfully",
      modules,
    });

  } catch (error) {

    console.error(
      "UPDATE MODULE ERROR:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Failed to update module",
    });

  }
};