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

export const createuserrole = async (req, res) => {
  try {
    // =====================================================
    // REQUEST BODY
    // =====================================================

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

      // ===================================================
      // DEVICE PERMISSIONS
      // ===================================================

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

    const cleanName =
      String(name).trim();

    const cleanEmail =
      String(email).trim().toLowerCase();

    // =====================================================
    // PASSWORD MATCH
    // =====================================================

    if (password !== confirm_password) {
      return res.status(400).json({
        success: false,
        message:
          "Password and Confirm Password not match",
      });
    }

    // =====================================================
    // ROLE VALIDATION
    // =====================================================

    const role = Number(role_id);

    if (!Number.isInteger(role)) {
      return res.status(400).json({
        success: false,
        message: "Invalid role_id",
      });
    }

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
        message:
          "Master Admin cannot be created",
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

    const created_by =
      Number(req.user.id);

    if (
      !Number.isInteger(created_by) ||
      created_by <= 0
    ) {
      return res.status(401).json({
        success: false,
        message: "Invalid logged-in user",
      });
    }

    // =====================================================
    // FIND CREATOR
    // =====================================================

    const creator =
      await findUserById(created_by);

    if (!creator) {
      return res.status(404).json({
        success: false,
        message: "Creator not found",
      });
    }

    const creatorRole =
      Number(creator.role_id);

    // =====================================================
    // NORMALIZE PARENT ID
    // =====================================================

    let selectedParentId = null;

    if (
      parent_id !== undefined &&
      parent_id !== null &&
      String(parent_id).trim() !== ""
    ) {
      selectedParentId =
        Number(parent_id);

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


    const allowedParentRoles = {
      [ROLES.CNF]: [
        ROLES.ADMIN,
      ],

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

    // =====================================================
    // PARENT DISABLED FIELD MAP
    // =====================================================

    const disabledFieldMap = {
      [ROLES.ADMIN]:
        "parent_admin_disabled",

      [ROLES.CNF]:
        "parent_cnf_disabled",

      [ROLES.SUPER_DISTRIBUTOR]:
        "parent_super_distributor_disabled",

      [ROLES.DISTRIBUTOR]:
        "parent_distributor_disabled",

      [ROLES.FOS]:
        "parent_fos_disabled",

      [ROLES.RETAILER]:
        "parent_retailer_disabled",

      [ROLES.SUB_RETAILER]:
        "parent_sub_retailer_disabled",

      [ROLES.EMPLOYEE]:
        "parent_employee_disabled",

      [ROLES.STAFF]:
        "parent_staff_disabled",
    };

    // =====================================================
    // STAFF
    // =====================================================

    if (role === ROLES.STAFF) {

      // ---------------------------------------------------
      // ONLY ADMIN CAN CREATE STAFF
      // ---------------------------------------------------

      if (creatorRole !== ROLES.ADMIN) {
        return res.status(403).json({
          success: false,
          message:
            "Only Admin can create Staff",
        });
      }

      // ---------------------------------------------------
      // STAFF PARENT
      // ---------------------------------------------------
      //
      // If Admin explicitly selects parent,
      // parent must be Admin.
      //
      // Otherwise logged-in Admin becomes parent.
      //
      // ---------------------------------------------------

      if (selectedParentId !== null) {

        const selectedParent =
          await findUserById(
            selectedParentId
          );

        if (!selectedParent) {
          return res.status(404).json({
            success: false,
            message:
              "Selected parent user not found",
          });
        }

        const parentRole =
          Number(selectedParent.role_id);

        if (
          parentRole !== ROLES.ADMIN
        ) {
          return res.status(403).json({
            success: false,
            message:
              "Staff parent must be an Admin",
          });
        }

        // -------------------------------------------------
        // CHECK ADMIN DISABLED STAFF
        // -------------------------------------------------

        const disabledField =
          disabledFieldMap[
            ROLES.STAFF
          ];

        if (
          disabledField &&
          Number(
            selectedParent[
              disabledField
            ] ?? 0
          ) === 1
        ) {
          return res.status(403).json({
            success: false,
            message:
              `${getRoleName(parentRole)} has disabled ${getRoleName(role)}`,
          });
        }

      } else {

        // -------------------------------------------------
        // NO PARENT SELECTED
        // LOGGED-IN ADMIN BECOMES PARENT
        // -------------------------------------------------

        selectedParentId =
          created_by;
      }
    }

    // =====================================================
    // NORMAL ROLES
    // =====================================================

    else {

      // ===================================================
      // EMPLOYEE / STAFF CANNOT CREATE USERS
      // ===================================================

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

      // ===================================================
      // CREATOR ROLE PERMISSION
      // ===================================================
      //
      // Master Admin:
      // Can create any valid role.
      //
      // Other users:
      // Cannot create same or higher role.
      //
      // ===================================================

      if (
        creatorRole !== ROLES.MASTER_ADMIN
      ) {

        if (role <= creatorRole) {
          return res.status(403).json({
            success: false,
            message:
              `You cannot create this role. Creator role: ${creatorRole}, Requested role: ${role}`,
          });
        }
      }

      // ===================================================
      // SELECTED PARENT VALIDATION
      // ===================================================

      if (selectedParentId !== null) {

        const selectedParent =
          await findUserById(
            selectedParentId
          );

        // -------------------------------------------------
        // PARENT NOT FOUND
        // -------------------------------------------------

        if (!selectedParent) {
          return res.status(404).json({
            success: false,
            message:
              "Selected parent user not found",
          });
        }

        const parentRole =
          Number(selectedParent.role_id);

        // -------------------------------------------------
        // IMPORTANT:
        // DO NOT CHECK:
        //
        // selectedParentId === created_by
        //
        // Creator itself can be the parent.
        // -------------------------------------------------

        // =================================================
        // CHECK ALLOWED PARENT ROLE
        // =================================================

        const allowedParents =
          allowedParentRoles[role] || [];

        if (
          !allowedParents.includes(
            parentRole
          )
        ) {
          return res.status(403).json({
            success: false,
            message:
              `${getRoleName(parentRole)} cannot be parent of ${getRoleName(role)}`,
          });
        }

        // =================================================
        // CHECK PARENT DISABLED THIS ROLE
        // =================================================

        const disabledField =
          disabledFieldMap[role];

        if (
          disabledField &&
          Number(
            selectedParent[
              disabledField
            ] ?? 0
          ) === 1
        ) {
          return res.status(403).json({
            success: false,
            message:
              `${getRoleName(parentRole)} has disabled ${getRoleName(role)}`,
          });
        }
      }

      // ===================================================
      // PARENT NOT SELECTED
      // ===================================================
      //
      // Master Admin:
      // parent can remain NULL.
      //
      // Other creators:
      // creator automatically becomes parent.
      //
      // ===================================================

      if (
        selectedParentId === null &&
        creatorRole !== ROLES.MASTER_ADMIN
      ) {
        selectedParentId =
          created_by;
      }
    }

    // =====================================================
    // EMAIL CHECK
    // =====================================================

    const existingUser =
      await findUserByEmail(
        cleanEmail
      );

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message:
          "Email already exists",
      });
    }

    // =====================================================
    // DEVICE PERMISSIONS DEFAULT
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

      for (
        const [field, value]
        of Object.entries(deviceFields)
      ) {

        // -----------------------------------------------
        // Missing value = 0
        // -----------------------------------------------

        if (
          value === undefined ||
          value === null ||
          value === ""
        ) {
          retailerDevices[field] = 0;
          continue;
        }

        const numericValue =
          Number(value);

        // -----------------------------------------------
        // Only 0 / 1 allowed
        // -----------------------------------------------

        if (
          ![0, 1].includes(
            numericValue
          )
        ) {
          return res.status(400).json({
            success: false,
            message:
              `${field} must be either 0 or 1`,
          });
        }

        retailerDevices[field] =
          numericValue;
      }
    }

    // =====================================================
    // HASH PASSWORD
    // =====================================================

    const hashPassword =
      await bcrypt.hash(
        password,
        10
      );

    // =====================================================
    // CREATE USER
    // =====================================================

    const userId =
      await createUserModel({

        // =================================================
        // BASIC DETAILS
        // =================================================

        organization_name,

        name:
          cleanName,

        email:
          cleanEmail,

        phone,

        password:
          hashPassword,

        company_address,

        country,

        state,

        city,

        // =================================================
        // ROLE
        // =================================================

        role_id:
          role,

        // =================================================
        // CREATOR
        // =================================================

        created_by,

        // =================================================
        // HIERARCHY PARENT
        // =================================================

        parent_id:
          selectedParentId,

        // =================================================
        // DEVICE PERMISSIONS
        // =================================================

        new_device:
          retailerDevices.new_device,

        old_device:
          retailerDevices.old_device,

        supreme_device:
          retailerDevices.supreme_device,

        pro_star:
          retailerDevices.pro_star,

        lite:
          retailerDevices.lite,

        google_tv:
          retailerDevices.google_tv,

        supreme_lock:
          retailerDevices.supreme_lock,
      });

    // =====================================================
    // SUCCESS RESPONSE
    // =====================================================

    return res.status(201).json({
      success: true,

      message:
        "User Registered Successfully",

      data: {

        // =================================================
        // USER
        // =================================================

        id:
          userId,

        organization_name,

        name:
          cleanName,

        email:
          cleanEmail,

        phone,

        role_id:
          role,

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

        parent_id:
          selectedParentId,

        // =================================================
        // DEVICE PERMISSIONS
        // =================================================

        new_device:
          retailerDevices.new_device,

        old_device:
          retailerDevices.old_device,

        supreme_device:
          retailerDevices.supreme_device,

        pro_star:
          retailerDevices.pro_star,

        lite:
          retailerDevices.lite,

        google_tv:
          retailerDevices.google_tv,

        supreme_lock:
          retailerDevices.supreme_lock,
      },
    });

  } catch (error) {

    // =====================================================
    // ERROR
    // =====================================================

    console.error(
      "Create User Error:",
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
    // CHECK USER STATUS
    // 1 = ACTIVE
    // 0 = INACTIVE
    // ==========================================

    if (Number(user.userStatus) === 0) {

      return res.status(403).json({
        success: false,
        message: "Your account is inactive",
      });

    }


    // ==========================================
    // CHECK PASSWORD
    // ==========================================

    const match =
      await bcrypt.compare(
        password,
        user.password
      );

    if (!match) {

      return res.status(401).json({
        success: false,
        message: "Invalid password",
      });

    }


    // ==========================================
    // JWT TOKEN
    // ==========================================

    const token =
      jwt.sign(
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
    // ==========================================

    return res.status(200).json({

      success: true,

      message:
        "Login Successful",

      token,

      user: {

        id:
          user.id,

        name:
          user.name,

        email:
          user.email,

        role_id:
          user.role_id,

        // ======================================
        // USER STATUS
        // ======================================

        userStatus:
          Number(user.userStatus),

        // ======================================
        // HIERARCHY DATA
        // ======================================

        parent_id:
          user.parent_id,

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

      },

    });

  }
  catch (error) {

    console.error(
      "Login Error:",
      error
    );

    return res.status(500).json({

      success: false,

      message:
        error.message,

    });

  }
};

// =========================
// GET ALL USERS
// =========================
export const getUsers = async (req, res) => {
  try {
    console.log("=================================");
    console.log("GET ALL STAFF DATA");
    console.log("REQ.USER:", req.user);
    console.log("=================================");

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
    // ROLE FILTER
    // ==========================================

    let role_id = null;

    if (
      req.query.role_id !== undefined &&
      req.query.role_id !== ""
    ) {
      role_id = Number(req.query.role_id);

      if (!Number.isInteger(role_id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid role_id",
        });
      }
    }

    // ==========================================
    // LOGGED-IN USER
    // ==========================================

    const loggedInUserId = Number(
      req.user?.id
    );

    const loggedInRoleId = Number(
      req.user?.role_id
    );

    console.log(
      "Logged In User ID:",
      loggedInUserId
    );

    console.log(
      "Logged In Role ID:",
      loggedInRoleId
    );

    console.log(
      "Requested Role ID:",
      role_id
    );

    // ==========================================
    // VALIDATE USER
    // ==========================================

    if (
      !Number.isInteger(loggedInUserId) ||
      loggedInUserId <= 0
    ) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized user",
      });
    }

    // ==========================================
    // GET HIERARCHY USERS
    // ==========================================

    const result = await getAllUsers(
      limit,
      offset,
      role_id,
      loggedInUserId,
      loggedInRoleId
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
      message:
        error.message ||
        "Failed to get users",
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
    const { role_id, parent_id, search } = req.query;

    // =========================================
    // VALIDATE ROLE
    // =========================================
    if (
      role_id === undefined ||
      role_id === null ||
      role_id === ""
    ) {
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

    // =========================================
    // PARENT ID
    // =========================================
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

    // =========================================
    // SEARCH
    // =========================================
    const searchTerm =
      typeof search === "string"
        ? search.trim()
        : "";

    // =========================================
    // BUILD QUERY
    // =========================================
    let whereClause = `
      WHERE role_id = ?
    `;

    const queryParams = [
      requestedRoleId,
    ];

    // Parent selected hai to uske direct
    // children hi dikhane hain
    if (selectedParentId !== null) {
      whereClause += `
        AND parent_id = ?
      `;

      queryParams.push(
        selectedParentId
      );
    }

    // Search
    if (searchTerm) {
      whereClause += `
        AND (
          name LIKE ?
          OR email LIKE ?
          OR phone LIKE ?
        )
      `;

      const searchValue =
        `%${searchTerm}%`;

      queryParams.push(
        searchValue,
        searchValue,
        searchValue
      );
    }

    // =========================================
    // GET USERS
    // =========================================
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
      ${whereClause}
      ORDER BY name ASC
      `,
      queryParams
    );

    // =========================================
    // RESPONSE
    // =========================================
    return res.status(200).json({
      success: true,

      create_role_id:
        requestedRoleId,

      parent_id:
        selectedParentId,

      current_role_id:
        requestedRoleId,

      current_role_name:
        getRoleName(
          requestedRoleId
        ),

      search:
        searchTerm,

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
  const connection = await db.getConnection();

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

    if (
      !Number.isInteger(userId) ||
      userId <= 0
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid User ID",
      });
    }

    const [existingRows] =
      await connection.query(
        `
        SELECT
          id,
          role_id,
          parent_id
        FROM users
        WHERE id = ?
        LIMIT 1
        `,
        [userId]
      );

    if (!existingRows.length) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    const currentRoleId = Number(
      role_id ??
        existingRows[0].role_id
    );

    let normalizedParentId =
      existingRows[0].parent_id ?? null;

    if (
      parent_id !== undefined
    ) {
      if (
        parent_id === null ||
        parent_id === ""
      ) {
        normalizedParentId = null;
      } else {
        normalizedParentId =
          Number(parent_id);

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
          normalizedParentId ===
          userId
        ) {
          return res.status(400).json({
            success: false,
            message:
              "User cannot be their own parent",
          });
        }

        const [parentRows] =
          await connection.query(
            `
            SELECT
              id,
              role_id
            FROM users
            WHERE id = ?
            LIMIT 1
            `,
            [normalizedParentId]
          );

        if (!parentRows.length) {
          return res.status(400).json({
            success: false,
            message:
              "Selected parent not found",
          });
        }
      }
    }

    await connection.beginTransaction();

    let updateQuery = `
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
        parent_id = ?,
        new_device = ?,
        old_device = ?,
        supreme_device = ?,
        pro_star = ?,
        lite = ?,
        google_tv = ?,
        supreme_lock = ?
    `;

    const updateValues = [
      organization_name || "",
      name || "",
      email || "",
      phone || "",
      company_address || "",
      country || "",
      state || "",
      city || "",

      normalizedParentId,

      Number(new_device ?? 0),
      Number(old_device ?? 0),
      Number(supreme_device ?? 0),
      Number(pro_star ?? 0),
      Number(lite ?? 0),
      Number(google_tv ?? 0),
      Number(supreme_lock ?? 0),
    ];

    if (
      password !== undefined &&
      password !== null &&
      password !== ""
    ) {
      updateQuery += `,
        password = ?
      `;

      updateValues.push(password);
    }

    updateQuery += `
      WHERE id = ?
    `;

    updateValues.push(userId);

    await connection.query(
      updateQuery,
      updateValues
    );

    if (
      Array.isArray(
        parent_hierarchy
      )
    ) {
      const hierarchy = parent_hierarchy
        .map((item) => ({
          role_id: Number(
            item?.role_id
          ),
          user_id: Number(
            item?.user_id
          ),
        }))
        .filter(
          (item) =>
            Number.isInteger(
              item.role_id
            ) &&
            item.role_id > 0 &&
            Number.isInteger(
              item.user_id
            ) &&
            item.user_id > 0
        );

      for (
        let index = 1;
        index < hierarchy.length;
        index++
      ) {
        const current =
          hierarchy[index];

        const previous =
          hierarchy[index - 1];

        if (
          current.user_id ===
          userId
        ) {
          continue;
        }

        if (
          current.user_id ===
          previous.user_id
        ) {
          continue;
        }

        const [selectedUserRows] =
          await connection.query(
            `
            SELECT
              id,
              role_id
            FROM users
            WHERE id = ?
            LIMIT 1
            `,
            [current.user_id]
          );

        if (
          !selectedUserRows.length
        ) {
          throw new Error(
            `Hierarchy user not found: ${current.user_id}`
          );
        }

        const actualRoleId =
          Number(
            selectedUserRows[0]
              .role_id
          );

        if (
          actualRoleId !==
          current.role_id
        ) {
          throw new Error(
            `Role mismatch for user ${current.user_id}`
          );
        }

        const [parentRows] =
          await connection.query(
            `
            SELECT
              id
            FROM users
            WHERE id = ?
            LIMIT 1
            `,
            [previous.user_id]
          );

        if (!parentRows.length) {
          throw new Error(
            `Parent user not found: ${previous.user_id}`
          );
        }

        await connection.query(
          `
          UPDATE users
          SET parent_id = ?
          WHERE id = ?
          AND role_id = ?
          `,
          [
            previous.user_id,
            current.user_id,
            current.role_id,
          ]
        );
      }
    }

    const [updatedRows] =
      await connection.query(
        `
        SELECT
          id,
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

    await connection.commit();

    return res.status(200).json({
      success: true,
      message:
        "Staff data updated successfully",
      data: updatedRows[0],
    });
  } catch (error) {
    await connection.rollback();

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
  } finally {
    connection.release();
  }
};

export const getStaffDataById = async (req, res) => {
  try {
    const { id } = req.params;

    // =========================================
    // VALIDATE ID
    // =========================================
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

    // =========================================
    // GET CURRENT USER
    // =========================================
    const [rows] = await db.query(
      `
      SELECT
        id,
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

    // =========================================
    // USER NOT FOUND
    // =========================================
    if (!rows || rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    const user = rows[0];

    // =========================================
    // GET PARENT CHAIN
    // =========================================
    const parentChain = [];

    let currentParentId = user.parent_id;

    // Safety limit - infinite loop se bachne ke liye
    let level = 0;
    const MAX_LEVEL = 20;

    while (
      currentParentId !== null &&
      currentParentId !== undefined &&
      Number(currentParentId) > 0 &&
      level < MAX_LEVEL
    ) {
      const [parentRows] = await db.query(
        `
        SELECT
          id,
          organization_name,
          role_id,
          name,
          email,
          phone,
          parent_id,
          company_address,
          country,
          state,
          city
        FROM users
        WHERE id = ?
        LIMIT 1
        `,
        [Number(currentParentId)]
      );

      // Parent nahi mila
      if (!parentRows || parentRows.length === 0) {
        break;
      }

      const parent = parentRows[0];

      // =========================================
      // ADD PARENT TO CHAIN
      // =========================================
      parentChain.push({
        id: parent.id,
        organization_name: parent.organization_name,
        role_id: parent.role_id,
        name: parent.name,
        email: parent.email,
        phone: parent.phone,
        parent_id: parent.parent_id,
        company_address: parent.company_address,
        country: parent.country,
        state: parent.state,
        city: parent.city,
      });

      // =========================================
      // MOVE TO NEXT PARENT
      // =========================================
      currentParentId = parent.parent_id;

      level++;
    }

    // =========================================
    // OPTIONAL:
    // HIGHEST PARENT FIRST
    // =========================================
    parentChain.reverse();

    // =========================================
    // SUCCESS RESPONSE
    // =========================================
    return res.status(200).json({
      success: true,
      message: "Staff data fetched successfully",

      data: {
        ...user,

        // Direct parent
        direct_parent:
          parentChain.length > 0
            ? parentChain[parentChain.length - 1]
            : null,

        // Complete hierarchy
        parent_chain: parentChain,
      },
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

    const targetUser = await findUserById(user_id);

    if (!targetUser) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // ==========================================
    // ORIGINAL LOGIN USER
    // ==========================================

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
    // 7 Sub Retailer
    // 8 Employee
    // 9 Staff
    // ==========================================

    const targetRoleId = Number(targetUser.role_id);

    // ==========================================
    // ORIGINAL USER KO WAPAS LOGIN ALLOW
    // ==========================================

    const isOriginalUser =
      Number(targetUser.id) === Number(originalUserId);

    // ==========================================
    // SAME CURRENT USER KO BHI LOGIN ALLOW
    //
    // Example:
    //
    // Distributor -> FOS
    // FOS -> FOS
    //
    // Same user hone ke wajah se block nahi hoga.
    // ==========================================

    const isSameCurrentUser =
      Number(targetUser.id) === Number(loggedInUser.id);

    // ==========================================
    // LOWER LEVEL VALIDATION
    // ==========================================

    if (
      !isOriginalUser &&
      !isSameCurrentUser &&
      targetRoleId <= originalRoleId
    ) {
      return res.status(403).json({
        success: false,
        message:
          "You can only login as a lower level user",
      });
    }

    // ==========================================
    // CREATE TARGET USER TOKEN
    // ==========================================

    const token = jwt.sign(
      {
        // CURRENT / TARGET USER
        id: targetUser.id,

        role_id: targetRoleId,

        email: targetUser.email,

        // ======================================
        // ORIGINAL LOGIN USER
        // ======================================

        original_user_id: originalUserId,

        original_role_id: originalRoleId,

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

      message: "Login as user successful",

      token,

      user: {
        id: targetUser.id,

        name: targetUser.name,

        email: targetUser.email,

        role_id: targetRoleId,

        parent_id:
          targetUser.parent_id || null,

        parent_admin_id:
          targetUser.parent_admin_id || null,

        parent_cnf_id:
          targetUser.parent_cnf_id || null,

        parent_super_distributor_id:
          targetUser.parent_super_distributor_id || null,

        parent_distributor_id:
          targetUser.parent_distributor_id || null,

        parent_fos_id:
          targetUser.parent_fos_id || null,

        parent_retailer_id:
          targetUser.parent_retailer_id || null,

        parent_employee_id:
          targetUser.parent_employee_id || null,

        parent_staff_id:
          targetUser.parent_staff_id || null,
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
// ADD MODULE
// =====================================================

export const addModule = async (req, res) => {
  try {

    // =================================================
    // ALLOWED ROLES
    // MASTER ADMIN = 0
    // EMPLOYEE     = 8
    // =================================================

    const userRole =
      Number(req.user?.role_id);

    if (
      userRole !== 0 &&
      userRole !== 8
    ) {

      return res.status(403).json({
        success: false,
        message:
          "Only Master Admin and Employee can add modules",
      });

    }


    // =================================================
    // GET MODULE DATA
    // =================================================

    const {
      module,
      sequence,
    } = req.body;


    // =================================================
    // MODULE VALIDATION
    // =================================================

    if (
      !module ||
      typeof module !== "string"
    ) {

      return res.status(400).json({
        success: false,
        message:
          "Module is required",
      });

    }


    const moduleName =
      module
        .trim()
        .toLowerCase();


    if (!moduleName) {

      return res.status(400).json({
        success: false,
        message:
          "Module name cannot be empty",
      });

    }


    // =================================================
    // SEQUENCE VALIDATION
    // =================================================

    const moduleSequence =
      Number(sequence);


    if (
      sequence === undefined ||
      sequence === null ||
      sequence === "" ||
      !Number.isInteger(moduleSequence) ||
      moduleSequence < 1
    ) {

      return res.status(400).json({
        success: false,
        message:
          "Valid sequence number is required. Example: 1, 2, 3",
      });

    }


    // =================================================
    // ICON VALIDATION
    // =================================================

    if (!req.file) {

      return res.status(400).json({
        success: false,
        message:
          "PNG module icon is required",
      });

    }


    // =================================================
    // PNG VALIDATION
    // =================================================

    if (
      req.file.mimetype !==
      "image/png"
    ) {

      return res.status(400).json({
        success: false,
        message:
          "Only PNG module icons are allowed",
      });

    }


    // =================================================
    // 20 KB ICON SIZE VALIDATION
    // =================================================

    const maxIconSize =
      20 * 1024;


    if (
      req.file.size >
      maxIconSize
    ) {

      return res.status(400).json({
        success: false,
        message:
          "PNG module icon must not exceed 20 KB",
      });

    }


    // =================================================
    // GET MASTER ADMIN
    // =================================================

    const [rows] =
      await db.query(
        `
        SELECT
          id,
          modules
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


    const masterAdmin =
      rows[0];


    // =================================================
    // GET EXISTING MODULES
    // =================================================

    let modules = [];


    if (masterAdmin.modules) {

      try {

        modules =
          typeof masterAdmin.modules ===
          "string"
            ? JSON.parse(
                masterAdmin.modules
              )
            : masterAdmin.modules;

      } catch (error) {

        console.error(
          "Modules JSON Parse Error:",
          error
        );

        modules = [];

      }

    }


    // =================================================
    // SAFETY
    // =================================================

    if (
      !Array.isArray(modules)
    ) {

      modules = [];

    }


    // =================================================
    // CONVERT OLD MODULE FORMAT
    // =================================================

    modules =
      modules.map(
        (item, index) => {

          // ===========================================
          // OLD STRING FORMAT
          // ===========================================

          if (
            typeof item === "string"
          ) {

            return {

              name:
                item,

              icon:
                null,

              sequence:
                index + 1,

              status:
                1,

            };

          }


          // ===========================================
          // OBJECT FORMAT
          // ===========================================

          return {

            ...item,

            sequence:
              Number(
                item?.sequence
              ) ||
              index + 1,

            status:
              Number(
                item?.status
              ) === 0
                ? 0
                : 1,

          };

        }
      );


    // =================================================
    // DUPLICATE MODULE CHECK
    // =================================================

    const alreadyExists =
      modules.some(
        (item) => {

          return (
            String(
              item?.name || ""
            )
              .trim()
              .toLowerCase() ===
            moduleName
          );

        }
      );


    // =================================================
    // DUPLICATE MODULE
    // =================================================

    if (alreadyExists) {

      return res.status(409).json({
        success: false,
        message:
          "Module already exists",
        modules,
      });

    }


    // =================================================
    // DUPLICATE SEQUENCE CHECK
    // =================================================

    const sequenceExists =
      modules.some(
        (item) => {

          return (
            Number(
              item?.sequence
            ) ===
            moduleSequence
          );

        }
      );


    if (sequenceExists) {

      return res.status(422).json({
        success: false,
        message:
          `Sequence ${moduleSequence} is already used`,
        modules,
      });

    }


    // =================================================
    // ICON PATH
    // =================================================

    const iconPath =
      `/uploads/modules/${req.file.filename}`;


    // =================================================
    // NEW MODULE
    // =================================================

    const newModule = {

      name:
        moduleName,

      icon:
        iconPath,

      sequence:
        moduleSequence,

      // 1 = Active
      // 0 = Inactive
      status:
        1,

    };


    // =================================================
    // ADD MODULE
    // =================================================

    modules.push(
      newModule
    );


    // =================================================
    // SORT MODULES BY SEQUENCE
    // =================================================

    modules.sort(
      (a, b) =>
        Number(
          a?.sequence ?? 999999
        ) -
        Number(
          b?.sequence ?? 999999
        )
    );


    // =================================================
    // UPDATE MASTER ADMIN
    // =================================================

    await db.query(
      `
      UPDATE users
      SET modules = ?
      WHERE id = ?
      AND role_id = 0
      `,
      [
        JSON.stringify(
          modules
        ),

        masterAdmin.id,
      ]
    );


    // =================================================
    // SUCCESS RESPONSE
    // =================================================

    return res.status(201).json({

      success:
        true,

      message:
        "Module added successfully",

      module:
        newModule,

      modules:
        modules,

    });


  } catch (error) {

    // =================================================
    // ERROR
    // =================================================

    console.error(
      "Add Module Error:",
      error
    );


    return res.status(500).json({

      success:
        false,

      message:
        "Internal server error",

      error:
        error.message,

    });

  }
};

// =====================================================
// GET MODULES
// =====================================================

export const getModules = async (
  req,
  res
) => {

  try {

    // =================================================
    // GET MASTER ADMIN
    // =================================================

    const [
      rows,
    ] = await db.query(
      `
      SELECT
        id,
        modules
      FROM users
      WHERE role_id = 0
      LIMIT 1
      `
    );


    // =================================================
    // MASTER ADMIN NOT FOUND
    // =================================================

    if (
      !rows.length
    ) {

      return res.status(404).json({

        success: false,

        message:
          "Master Admin not found",

      });

    }


    const masterAdmin =
      rows[0];


    // =================================================
    // PARSE MODULES
    // =================================================

    let modules = [];


    if (
      masterAdmin.modules
    ) {

      try {

        modules =
          typeof masterAdmin.modules ===
          "string"

            ? JSON.parse(
                masterAdmin.modules
              )

            : masterAdmin.modules;

      }
      catch (error) {

        console.error(
          "MODULES JSON PARSE ERROR:",
          error
        );

        return res.status(500).json({

          success: false,

          message:
            "Invalid modules data",

        });

      }

    }


    // =================================================
    // SAFETY CHECK
    // =================================================

    if (
      !Array.isArray(
        modules
      )
    ) {

      modules = [];

    }


    // =================================================
    // CONVERT / NORMALIZE MODULES
    // =================================================

    modules =
      modules.map(
        (item, index) => {

          // ===========================================
          // OLD STRING FORMAT
          // ===========================================

          if (
            typeof item === "string"
          ) {

            return {

              name:
                item,

              icon:
                null,

              sequence:
                index + 1,

              // OLD MODULES DEFAULT ACTIVE
              status:
                1,

            };

          }


          // ===========================================
          // OBJECT FORMAT
          // ===========================================

          const sequence =
            Number(
              item?.sequence
            );


          const status =
            Number(
              item?.status
            );


          return {

            name:
              item?.name ||
              "",

            icon:
              item?.icon ||
              null,

            sequence:
              Number.isInteger(
                sequence
              ) &&
              sequence > 0

                ? sequence

                : index + 1,

            // =========================================
            // STATUS
            //
            // 1 = ACTIVE / SHOW
            // 0 = INACTIVE / HIDE
            //
            // Agar purane record me status nahi hai
            // toh default 1
            // =========================================

            status:
              status === 0
                ? 0
                : 1,

          };

        }
      );


    // =================================================
    // SORT BY SEQUENCE
    // =================================================

    modules.sort(
      (a, b) => {

        return (
          Number(
            a?.sequence ?? 999999
          ) -
          Number(
            b?.sequence ?? 999999
          )
        );

      }
    );


    // =================================================
    // ACTIVE / INACTIVE COUNT
    // =================================================

    const activeModules =
      modules.filter(
        (item) =>
          Number(
            item?.status
          ) === 1
      );


    const inactiveModules =
      modules.filter(
        (item) =>
          Number(
            item?.status
          ) === 0
      );


    // =================================================
    // SUCCESS
    // =================================================

    return res.status(200).json({

      success: true,

      count:
        modules.length,

      activeCount:
        activeModules.length,

      inactiveCount:
        inactiveModules.length,

      modules,

    });


  }
  catch (error) {

    // =================================================
    // ERROR
    // =================================================

    console.error(
      "GET MODULES ERROR:",
      error
    );


    return res.status(500).json({

      success: false,

      message:
        "Failed to get modules",

      error:
        error?.message,

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

    // =================================================
    // VALIDATION
    // =================================================

    if (!module || typeof module !== "string") {

      return res.status(400).json({
        success: false,
        message: "Module name is required",
      });

    }

    const moduleName =
      module.trim().toLowerCase();


    if (!moduleName) {

      return res.status(400).json({
        success: false,
        message: "Module name cannot be empty",
      });

    }


    // =================================================
    // GET MASTER ADMIN
    // =================================================

    const [rows] = await db.query(
      `
      SELECT
        id,
        modules
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


    const masterAdmin =
      rows[0];


    // =================================================
    // GET MODULES
    // =================================================

    let modules = [];


    if (masterAdmin.modules) {

      try {

        modules =
          typeof masterAdmin.modules === "string"
            ? JSON.parse(masterAdmin.modules)
            : masterAdmin.modules;

      } catch (error) {

        console.error(
          "MODULE JSON PARSE ERROR:",
          error
        );

        modules = [];

      }

    }


    // =================================================
    // SAFETY
    // =================================================

    if (!Array.isArray(modules)) {

      modules = [];

    }


    console.log(
      "OLD MODULES:",
      modules
    );


    // =================================================
    // FIND MODULE
    // =================================================

    const moduleExists =
      modules.some((item) => {

        // New format:
        // {
        //   name: "varunn",
        //   icon: "/uploads/modules/abc.png"
        // }

        if (
          typeof item === "object" &&
          item !== null
        ) {

          return (
            String(item?.name || "")
              .trim()
              .toLowerCase() === moduleName
          );

        }


        // Old format:
        // "varunn"

        return (
          String(item || "")
            .trim()
            .toLowerCase() === moduleName
        );

      });


    if (!moduleExists) {

      return res.status(404).json({
        success: false,
        message: `Module "${module}" not found`,
      });

    }


    // =================================================
    // GET MODULE ICON BEFORE DELETE
    // =================================================

    const deletedModule =
      modules.find((item) => {

        if (
          typeof item === "object" &&
          item !== null
        ) {

          return (
            String(item?.name || "")
              .trim()
              .toLowerCase() === moduleName
          );

        }

        return (
          String(item || "")
            .trim()
            .toLowerCase() === moduleName
        );

      });


    console.log(
      "DELETED MODULE:",
      deletedModule
    );


    // =================================================
    // DELETE MODULE
    // =================================================

    const updatedModules =
      modules.filter((item) => {

        if (
          typeof item === "object" &&
          item !== null
        ) {

          return (
            String(item?.name || "")
              .trim()
              .toLowerCase() !== moduleName
          );

        }

        return (
          String(item || "")
            .trim()
            .toLowerCase() !== moduleName
        );

      });


    console.log(
      "UPDATED MODULES:",
      updatedModules
    );


    // =================================================
    // UPDATE DATABASE
    // =================================================

    const [result] =
      await db.query(
        `
        UPDATE users
        SET modules = ?
        WHERE id = ?
        AND role_id = 0
        `,
        [
          JSON.stringify(
            updatedModules
          ),
          masterAdmin.id,
        ]
      );


    console.log(
      "DELETE UPDATE RESULT:",
      result
    );


    // =================================================
    // SUCCESS
    // =================================================

    return res.status(200).json({

      success: true,

      message:
        `Module "${module}" deleted successfully`,

      deletedModule:
        deletedModule,

      modules:
        updatedModules,

    });


  } catch (error) {

    console.error(
      "DELETE MODULE ERROR:",
      error
    );


    return res.status(500).json({

      success: false,

      message:
        "Failed to delete module",

      error:
        error.message,

    });

  }

};


export const updateModule = async (req, res) => {
  try {
    if (Number(req.user?.role_id) !== 0) {
      if (req.file) {
        const uploadedFilePath = path.join(
          uploadDir,
          req.file.filename
        );

        if (fs.existsSync(uploadedFilePath)) {
          fs.unlinkSync(uploadedFilePath);
        }
      }

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

    if (
      typeof oldModule !== "string" ||
      !oldModule.trim()
    ) {
      if (req.file) {
        const uploadedFilePath = path.join(
          uploadDir,
          req.file.filename
        );

        if (fs.existsSync(uploadedFilePath)) {
          fs.unlinkSync(uploadedFilePath);
        }
      }

      return res.status(400).json({
        success: false,
        message: "Old module name is required",
      });
    }

    const hasNewModule =
      typeof newModule === "string" &&
      newModule.trim() !== "";

    const hasNewSequence =
      newSequence !== undefined &&
      newSequence !== null &&
      String(newSequence).trim() !== "";

    const hasNewStatus =
      status !== undefined &&
      status !== null &&
      String(status).trim() !== "";

    const hasNewIcon = !!req.file;

    if (
      !hasNewModule &&
      !hasNewSequence &&
      !hasNewStatus &&
      !hasNewIcon
    ) {
      if (req.file) {
        const uploadedFilePath = path.join(
          uploadDir,
          req.file.filename
        );

        if (fs.existsSync(uploadedFilePath)) {
          fs.unlinkSync(uploadedFilePath);
        }
      }

      return res.status(400).json({
        success: false,
        message: "At least one field is required to update",
      });
    }

    let sequence = null;

    if (hasNewSequence) {
      sequence = Number(newSequence);

      if (
        !Number.isInteger(sequence) ||
        sequence < 1
      ) {
        if (req.file) {
          const uploadedFilePath = path.join(
            uploadDir,
            req.file.filename
          );

          if (fs.existsSync(uploadedFilePath)) {
            fs.unlinkSync(uploadedFilePath);
          }
        }

        return res.status(400).json({
          success: false,
          message: "Valid sequence number is required",
        });
      }
    }

    let moduleStatus = null;

    if (hasNewStatus) {
      moduleStatus = Number(status);

      if (
        moduleStatus !== 0 &&
        moduleStatus !== 1
      ) {
        if (req.file) {
          const uploadedFilePath = path.join(
            uploadDir,
            req.file.filename
          );

          if (fs.existsSync(uploadedFilePath)) {
            fs.unlinkSync(uploadedFilePath);
          }
        }

        return res.status(400).json({
          success: false,
          message: "Status must be either 0 or 1",
        });
      }
    }

    const oldModuleName = oldModule
      .trim()
      .toLowerCase();

    const newModuleName = hasNewModule
      ? newModule.trim().toLowerCase()
      : null;

    const [rows] = await db.query(`
      SELECT
        id,
        modules
      FROM users
      WHERE role_id = 0
      LIMIT 1
    `);

    if (!rows.length) {
      if (req.file) {
        const uploadedFilePath = path.join(
          uploadDir,
          req.file.filename
        );

        if (fs.existsSync(uploadedFilePath)) {
          fs.unlinkSync(uploadedFilePath);
        }
      }

      return res.status(404).json({
        success: false,
        message: "Master Admin not found",
      });
    }

    const masterAdmin = rows[0];

    let modules = masterAdmin.modules;

    if (!modules) {
      modules = [];
    } else if (typeof modules === "string") {
      try {
        modules = JSON.parse(modules);
      } catch (error) {
        if (req.file) {
          const uploadedFilePath = path.join(
            uploadDir,
            req.file.filename
          );

          if (fs.existsSync(uploadedFilePath)) {
            fs.unlinkSync(uploadedFilePath);
          }
        }

        return res.status(500).json({
          success: false,
          message: "Invalid modules data",
        });
      }
    }

    if (!Array.isArray(modules)) {
      if (req.file) {
        const uploadedFilePath = path.join(
          uploadDir,
          req.file.filename
        );

        if (fs.existsSync(uploadedFilePath)) {
          fs.unlinkSync(uploadedFilePath);
        }
      }

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
        sequence: Number(
          item?.sequence ?? index + 1
        ),
        status:
          Number(item?.status ?? 1) === 0
            ? 0
            : 1,
      };
    });

    const moduleIndex = modules.findIndex(
      (item) =>
        String(item?.name || "")
          .trim()
          .toLowerCase() === oldModuleName
    );

    if (moduleIndex === -1) {
      if (req.file) {
        const uploadedFilePath = path.join(
          uploadDir,
          req.file.filename
        );

        if (fs.existsSync(uploadedFilePath)) {
          fs.unlinkSync(uploadedFilePath);
        }
      }

      return res.status(404).json({
        success: false,
        message: `Old module "${oldModule}" not found`,
      });
    }

    const currentModule = modules[moduleIndex];

    if (hasNewModule) {
      const duplicateModule = modules.some(
        (item, index) => {
          if (index === moduleIndex) {
            return false;
          }

          return (
            String(item?.name || "")
              .trim()
              .toLowerCase() === newModuleName
          );
        }
      );

      if (duplicateModule) {
        if (req.file) {
          const uploadedFilePath = path.join(
            uploadDir,
            req.file.filename
          );

          if (fs.existsSync(uploadedFilePath)) {
            fs.unlinkSync(uploadedFilePath);
          }
        }

        return res.status(409).json({
          success: false,
          message: `Module "${newModule}" already exists`,
        });
      }
    }

    if (hasNewSequence) {
      const duplicateSequence = modules.some(
        (item, index) => {
          if (index === moduleIndex) {
            return false;
          }

          return (
            Number(item?.sequence) === sequence
          );
        }
      );

      if (duplicateSequence) {
        if (req.file) {
          const uploadedFilePath = path.join(
            uploadDir,
            req.file.filename
          );

          if (fs.existsSync(uploadedFilePath)) {
            fs.unlinkSync(uploadedFilePath);
          }
        }

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
      : Number(
          currentModule?.sequence ||
          moduleIndex + 1
        );

    const finalStatus = hasNewStatus
      ? moduleStatus
      : Number(
          currentModule?.status ?? 1
        ) === 0
        ? 0
        : 1;

    let finalIcon = currentModule?.icon || null;

    if (hasNewIcon) {
      finalIcon = `/uploads/modules/${req.file.filename}`;
    }

    const previousStatus = Number(
      currentModule?.status ?? 1
    );

    modules[moduleIndex] = {
      name: finalName,
      icon: finalIcon,
      sequence: finalSequence,
      status: finalStatus,
    };

    modules.sort(
      (a, b) =>
        Number(a.sequence) -
        Number(b.sequence)
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

      const inactiveRoleId =
        roleMap[oldModuleName];

      if (inactiveRoleId) {
        const [inactiveUsers] = await db.query(
          `
          SELECT
            id,
            parent_id
          FROM users
          WHERE role_id = ?
          `,
          [inactiveRoleId]
        );

        for (const inactiveUser of inactiveUsers) {
          if (!inactiveUser.parent_id) {
            continue;
          }

          await db.query(
            `
            UPDATE users
            SET parent_id = ?
            WHERE parent_id = ?
            `,
            [
              inactiveUser.parent_id,
              inactiveUser.id,
            ]
          );
        }
      }
    }

    await db.query(
      `
      UPDATE users
      SET modules = ?
      WHERE id = ?
      AND role_id = 0
      `,
      [
        JSON.stringify(modules),
        masterAdmin.id,
      ]
    );

    if (
      hasNewIcon &&
      oldIcon &&
      oldIcon !== finalIcon
    ) {
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
    console.error(
      "UPDATE MODULE ERROR:",
      error
    );

    if (req.file) {
      try {
        const filePath = path.join(
          uploadDir,
          req.file.filename
        );

        if (fs.existsSync(filePath)) {
          fs.unlinkSync(filePath);
        }
      } catch (fileError) {
        console.error(
          "FILE DELETE ERROR:",
          fileError
        );
      }
    }

    return res.status(500).json({
      success: false,
      message:
        error?.message ||
        "Failed to update module",
    });
  }
};

export const updateUserStatus = async (req, res) => {
  try {

    // =====================================================
    // GET DATA
    // =====================================================

    const {
      user_id,
      userStatus,
    } = req.body;


    // =====================================================
    // VALIDATION
    // =====================================================

    if (!user_id) {

      return res.status(400).json({
        success: false,
        message: "User ID is required",
      });

    }


    // =====================================================
    // BOOLEAN VALIDATION
    // 0 = INACTIVE
    // 1 = ACTIVE
    // =====================================================

    if (
      Number(userStatus) !== 0 &&
      Number(userStatus) !== 1
    ) {

      return res.status(400).json({
        success: false,
        message:
          "userStatus must be 0 (Inactive) or 1 (Active)",
      });

    }


    const status =
      Number(userStatus);


    // =====================================================
    // CHECK USER
    // =====================================================

    const [users] =
      await db.query(
        `
        SELECT
          id,
          name,
          userStatus
        FROM users
        WHERE id = ?
        LIMIT 1
        `,
        [user_id]
      );


    if (!users.length) {

      return res.status(404).json({
        success: false,
        message: "User not found",
      });

    }


    // =====================================================
    // UPDATE STATUS
    // =====================================================

    await db.query(
      `
      UPDATE users
      SET userStatus = ?
      WHERE id = ?
      `,
      [
        status,
        user_id,
      ]
    );


    // =====================================================
    // RESPONSE STATUS
    // =====================================================

    const statusText =
      status === 1
        ? "Active"
        : "Inactive";


    // =====================================================
    // SUCCESS
    // =====================================================

    return res.status(200).json({

      success: true,

      message:
        `User status updated to ${statusText}`,

      user: {
        id: users[0].id,

        name:
          users[0].name,

        userStatus:
          status,

        status:
          statusText,
      },

    });

  } catch (error) {

    console.error(
      "UPDATE USER STATUS ERROR:",
      error
    );

    return res.status(500).json({

      success: false,

      message:
        "Failed to update user status",

      error:
        error.message,

    });

  }
};