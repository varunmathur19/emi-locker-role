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


// =========================
// create the user(onbaord)
// =========================
export const createuserrole = async (req, res) => {
  try {

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

      // =========================
      // HIERARCHY
      // =========================
      parent_admin_id,
      parent_cnf_id,
      parent_super_distributor_id,
      parent_distributor_id,
      parent_fos_id,
      parent_retailer_id,
      parent_staff_id,

      // =========================
      // DEVICE PERMISSIONS
      // =========================
      new_device,
      old_device,
      supreme_device,
      pro_star,
      lite,
      google_tv,
      supreme_lock

    } = req.body;


    // =====================================================
    // LOGGED-IN USER
    // =====================================================

    const created_by = req.user.id;


    // =====================================================
    // CREATOR CHECK
    // =====================================================

    const creator = await findUserById(created_by);

    if (!creator) {
      return res.status(404).json({
        success: false,
        message: "Creator not found"
      });
    }


    // =====================================================
    // ROLE VALIDATION
    // =====================================================

    if (!isValidRole(role_id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid role_id"
      });
    }

    const role = Number(role_id);
    const creatorRole = Number(creator.role_id);


    // =====================================================
    // STAFF CREATE RULE
    // Only Admin can create Staff
    // =====================================================

    if (role === ROLES.STAFF) {

      if (creatorRole !== ROLES.ADMIN) {

        return res.status(403).json({
          success: false,
          message: "Only Admin can create Staff"
        });

      }

    }


    // =====================================================
    // NORMAL ROLE HIERARCHY
    // =====================================================

    if (creatorRole !== ROLES.STAFF) {

      if (
        role !== ROLES.STAFF &&
        role <= creatorRole
      ) {

        return res.status(400).json({
          success: false,
          message: "You cannot create same or upper level role"
        });

      }

    }


    // =====================================================
    // CNF
    // CNF -> Admin
    // =====================================================

    if (role === ROLES.CNF) {

      if (!parent_admin_id) {

        return res.status(400).json({
          success: false,
          message: "parent_admin_id is required"
        });

      }

    }


    // =====================================================
    // SUPER DISTRIBUTOR
    // Super -> CNF -> Admin
    // =====================================================

    if (role === ROLES.SUPER_DISTRIBUTOR) {

      if (!parent_admin_id) {

        return res.status(400).json({
          success: false,
          message: "parent_admin_id is required"
        });

      }

      if (!parent_cnf_id) {

        return res.status(400).json({
          success: false,
          message: "parent_cnf_id is required"
        });

      }

    }


    // =====================================================
    // DISTRIBUTOR
    // Distributor -> Super -> CNF -> Admin
    // =====================================================

    if (role === ROLES.DISTRIBUTOR) {

      if (!parent_admin_id) {

        return res.status(400).json({
          success: false,
          message: "parent_admin_id is required"
        });

      }

      if (!parent_cnf_id) {

        return res.status(400).json({
          success: false,
          message: "parent_cnf_id is required"
        });

      }

      if (!parent_super_distributor_id) {

        return res.status(400).json({
          success: false,
          message: "parent_super_distributor_id is required"
        });

      }

    }


    // =====================================================
    // FOS
    // FOS -> Distributor -> Super -> CNF -> Admin
    // =====================================================

    if (role === ROLES.FOS) {

      if (!parent_admin_id) {

        return res.status(400).json({
          success: false,
          message: "parent_admin_id is required"
        });

      }

      if (!parent_cnf_id) {

        return res.status(400).json({
          success: false,
          message: "parent_cnf_id is required"
        });

      }

      if (!parent_super_distributor_id) {

        return res.status(400).json({
          success: false,
          message: "parent_super_distributor_id is required"
        });

      }

      if (!parent_distributor_id) {

        return res.status(400).json({
          success: false,
          message: "parent_distributor_id is required"
        });

      }

    }


    // =====================================================
    // RETAILER
    // Retailer -> FOS -> Distributor -> Super -> CNF -> Admin
    // =====================================================

    if (role === ROLES.RETAILER) {

      if (!parent_admin_id) {

        return res.status(400).json({
          success: false,
          message: "parent_admin_id is required"
        });

      }

      if (!parent_cnf_id) {

        return res.status(400).json({
          success: false,
          message: "parent_cnf_id is required"
        });

      }

      if (!parent_super_distributor_id) {

        return res.status(400).json({
          success: false,
          message: "parent_super_distributor_id is required"
        });

      }

      if (!parent_distributor_id) {

        return res.status(400).json({
          success: false,
          message: "parent_distributor_id is required"
        });

      }

      if (!parent_fos_id) {

        return res.status(400).json({
          success: false,
          message: "parent_fos_id is required"
        });

      }

    }


    // =====================================================
    // EMPLOYEE
    // Employee -> Retailer -> FOS -> Distributor
    // -> Super -> CNF -> Admin
    // =====================================================

    if (role === ROLES.EMPLOYEE) {

      if (!parent_admin_id) {

        return res.status(400).json({
          success: false,
          message: "parent_admin_id is required"
        });

      }

      if (!parent_cnf_id) {

        return res.status(400).json({
          success: false,
          message: "parent_cnf_id is required"
        });

      }

      if (!parent_super_distributor_id) {

        return res.status(400).json({
          success: false,
          message: "parent_super_distributor_id is required"
        });

      }

      if (!parent_distributor_id) {

        return res.status(400).json({
          success: false,
          message: "parent_distributor_id is required"
        });

      }

      if (!parent_fos_id) {

        return res.status(400).json({
          success: false,
          message: "parent_fos_id is required"
        });

      }

      if (!parent_retailer_id) {

        return res.status(400).json({
          success: false,
          message: "parent_retailer_id is required"
        });

      }

    }


    // =====================================================
    // STAFF
    // Staff -> Admin
    // =====================================================

    if (role === ROLES.STAFF) {

      if (creatorRole !== ROLES.ADMIN) {

        return res.status(403).json({
          success: false,
          message: "Only Admin can create Staff"
        });

      }

      if (!parent_admin_id) {

        return res.status(400).json({
          success: false,
          message: "parent_admin_id is required for Staff"
        });

      }

    }


    // =====================================================
    // EMAIL CHECK
    // =====================================================

    const existing = await findUserByEmail(email);

    if (existing) {

      return res.status(400).json({
        success: false,
        message: "Email already exists"
      });

    }


    // =====================================================
    // PASSWORD CHECK
    // =====================================================

    if (password !== confirm_password) {

      return res.status(400).json({
        success: false,
        message: "Password and Confirm Password not match"
      });

    }


    // =====================================================
    // RETAILER DEVICE VALIDATION
    // =====================================================

    if (role === ROLES.RETAILER) {

      const deviceFields = [
        new_device,
        old_device,
        supreme_device,
        pro_star,
        lite,
        google_tv,
        supreme_lock
      ];

      if (
        deviceFields.some(
          value => value === undefined
        )
      ) {

        return res.status(400).json({
          success: false,
          message: "All retailer device fields are required"
        });

      }

      if (
        deviceFields.some(
          value => ![0, 1].includes(Number(value))
        )
      ) {

        return res.status(400).json({
          success: false,
          message: "Device fields only accept 0 or 1"
        });

      }

    }


    // =====================================================
    // HASH PASSWORD
    // =====================================================

    const hashPassword =
      await bcrypt.hash(password, 10);


    // =====================================================
    // CREATE USER
    // =====================================================

    const userId = await createUserModel({

      organization_name,

      role_id: role,

      name,

      email,

      phone,

      password: hashPassword,

      company_address,

      country,

      state,

      city,

      created_by,


      // =================================================
      // HIERARCHY IDS
      // =================================================

      parent_admin_id:
        parent_admin_id
          ? Number(parent_admin_id)
          : null,

      parent_cnf_id:
        parent_cnf_id
          ? Number(parent_cnf_id)
          : null,

      parent_super_distributor_id:
        parent_super_distributor_id
          ? Number(parent_super_distributor_id)
          : null,

      parent_distributor_id:
        parent_distributor_id
          ? Number(parent_distributor_id)
          : null,

      parent_fos_id:
        parent_fos_id
          ? Number(parent_fos_id)
          : null,

      parent_retailer_id:
        parent_retailer_id
          ? Number(parent_retailer_id)
          : null,

      parent_staff_id:
        parent_staff_id
          ? Number(parent_staff_id)
          : null,


      // =================================================
      // DEVICE PERMISSIONS
      // =================================================

      new_device:
        Number(new_device || 0),

      old_device:
        Number(old_device || 0),

      supreme_device:
        Number(supreme_device || 0),

      pro_star:
        Number(pro_star || 0),

      lite:
        Number(lite || 0),

      google_tv:
        Number(google_tv || 0),

      supreme_lock:
        Number(supreme_lock || 0)

    });


    // =====================================================
    // RESPONSE
    // =====================================================

    return res.status(201).json({

      success: true,

      message: "User Registered Successfully",

      data: {

        id: userId,

        organization_name,

        role_id: role,

        name,

        email,

        phone,

        company_address,

        country,

        state,

        city,

        created_by,


        // =================================================
        // HIERARCHY
        // =================================================

        parent_admin_id:
          parent_admin_id
            ? Number(parent_admin_id)
            : null,

        parent_cnf_id:
          parent_cnf_id
            ? Number(parent_cnf_id)
            : null,

        parent_super_distributor_id:
          parent_super_distributor_id
            ? Number(parent_super_distributor_id)
            : null,

        parent_distributor_id:
          parent_distributor_id
            ? Number(parent_distributor_id)
            : null,

        parent_fos_id:
          parent_fos_id
            ? Number(parent_fos_id)
            : null,

        parent_retailer_id:
          parent_retailer_id
            ? Number(parent_retailer_id)
            : null,

        parent_staff_id:
          parent_staff_id
            ? Number(parent_staff_id)
            : null

      }

    });


  } catch (error) {

    console.log("Create User Error:", error);

    return res.status(500).json({

      success: false,

      message: error.message

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

    console.log("=================================");
    console.log("GET DROPDOWN USERS");
    console.log("Role ID:", roleId);
    console.log("Parent ID:", parentId);
    console.log("SQL:", sql);
    console.log("Values:", values);

    // =====================================================
    // EXECUTE QUERY
    // =====================================================

    const [rows] = await db.query(sql, values);

    console.log("Dropdown Users:", rows);
    console.log("Total Users:", rows.length);

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