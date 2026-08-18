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
export const getUsers = async(req,res)=>{

try{

const page = Number(req.query.page) || 1;

const limit = Number(req.query.limit) || 10;


const offset = (page - 1) * limit;


const role_id = req.query.role_id || null;



const result = await getAllUsers(
    limit,
    offset,
    role_id
);



res.status(200).json({

success:true,


pagination:{
    currentPage:page,
    totalPages:Math.ceil(result.total / limit),
    limit:limit
},


totalUsers:result.total,


data:result.users


});


}
catch(error){

res.status(500).json({

success:false,
message:error.message

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

    const roleId = Number(role_id);
    const parentId = parent_id ? Number(parent_id) : null;

    if (Number.isNaN(roleId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid role_id",
      });
    }

    if (parent_id && Number.isNaN(parentId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid parent_id",
      });
    }

    let sql = "";
    let values = [];

    // =====================================================
    // COMMON COLUMNS
    // =====================================================

    const columns = `
      id,
      name,
      role_id,
      created_by,
      parent_admin_id,
      parent_cnf_id,
      parent_super_distributor_id,
      parent_distributor_id,
      parent_fos_id,
      parent_retailer_id,
      parent_staff_id
    `;

    // =====================================================
    // ADMIN
    // =====================================================

    if (roleId === 1) {
      sql = `
        SELECT
          ${columns}
        FROM users
        WHERE role_id = 1
        ORDER BY name
      `;
    }

    // =====================================================
    // FOS
    // =====================================================
    //
    // Distributor select:
    //
    // role_id = 5
    // parent_id = Distributor ID
    //
    // FOS ke parent_distributor_id me Distributor ID hona chahiye.
    //
    // =====================================================

    else if (roleId === 5) {
      if (!parentId) {
        sql = `
          SELECT
            ${columns}
          FROM users
          WHERE role_id = 5
          ORDER BY name
        `;
      } else {
        sql = `
          SELECT
            ${columns}
          FROM users
          WHERE role_id = 5
          AND parent_distributor_id = ?
          ORDER BY name
        `;

        values = [parentId];
      }
    }

    // =====================================================
    // RETAILER
    // =====================================================
    //
    // Retailer ke 2 possible cases hain:
    //
    // CASE 1:
    // Distributor -> FOS -> Retailer
    //
    // parent_fos_id = FOS ID
    //
    // CASE 2:
    // Distributor -> Direct Retailer
    //
    // created_by = Distributor ID
    //
    // Isliye Distributor select karne par dono check karenge:
    //
    // parent_distributor_id = Distributor ID
    //
    // OR
    //
    // created_by = Distributor ID
    //
    // =====================================================

    else if (roleId === 6) {
      if (!parentId) {
        sql = `
          SELECT
            ${columns}
          FROM users
          WHERE role_id = 6
          ORDER BY name
        `;
      } else {
        sql = `
          SELECT
            ${columns}
          FROM users
          WHERE role_id = 6
          AND (
            parent_distributor_id = ?
            OR created_by = ?
          )
          ORDER BY name
        `;

        values = [parentId, parentId];
      }
    }

    // =====================================================
    // OTHER ROLES
    // =====================================================

    else {
      // ---------------------------------------------------
      // NO PARENT
      // ---------------------------------------------------

      if (!parentId) {
        sql = `
          SELECT
            ${columns}
          FROM users
          WHERE role_id = ?
          ORDER BY name
        `;

        values = [roleId];
      }

      // ---------------------------------------------------
      // PARENT KE UNDER USERS
      // ---------------------------------------------------

      else {
        sql = `
          SELECT
            ${columns}
          FROM users
          WHERE role_id = ?
          AND created_by = ?
          ORDER BY name
        `;

        values = [
          roleId,
          parentId,
        ];
      }
    }

    // =====================================================
    // DEBUG
    // =====================================================

 


    // =====================================================
    // EXECUTE QUERY
    // =====================================================

    const [rows] = await db.query(sql, values);



    // =====================================================
    // RESPONSE
    // =====================================================

    return res.status(200).json({
      success: true,
      total: rows.length,
      data: rows,
    });

  } catch (error) {
    console.error(
      "getDropdownUsers Error:",
      error
    );

    return res.status(500).json({
      success: false,
      message: error.message,
    });
  }
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