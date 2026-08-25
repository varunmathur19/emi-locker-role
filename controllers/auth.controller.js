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

    // =====================================================
    // ALLOWED PARENT ROLES
    // =====================================================
    //
    // Admin
    //    ↓
    // CNF
    //    ↓
    // Super Distributor
    //    ↓
    // Distributor
    //    ↓
    // FOS
    //    ↓
    // Retailer
    //    ↓
    // Sub Retailer
    //
    // Employee can have the configured hierarchy parents.
    //
    // =====================================================

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
    const {
      role_id,
      parent_id,
      search,
    } = req.query;

    // =====================================================
    // VALIDATE ROLE ID
    // =====================================================

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
      Number.isNaN(requestedRoleId) ||
      !Number.isInteger(requestedRoleId)
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid role_id",
      });
    }

    // =====================================================
    // SUPPORTED ROLES
    // =====================================================

    const validRoles = [
      1, // Admin
      2, // CNF
      3, // Super Distributor
      4, // Distributor
      5, // FOS
      6, // Retailer
      7, // Sub Retailer
      8, // Employee
      9, // Staff
    ];

    if (!validRoles.includes(requestedRoleId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid or unsupported role_id",
      });
    }

    // =====================================================
    // DISABLED FIELD MAP
    // =====================================================

    const disabledFieldMap = {
      1: "parent_admin_disabled",
      2: "parent_cnf_disabled",
      3: "parent_super_distributor_disabled",
      4: "parent_distributor_disabled",
      5: "parent_fos_disabled",
      6: "parent_retailer_disabled",
      7: "parent_sub_retailer_disabled",
      8: "parent_employee_disabled",
      9: "parent_staff_disabled",
    };

    const disabledField =
      disabledFieldMap[requestedRoleId];

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

      if (
        Number.isNaN(selectedParentId) ||
        !Number.isInteger(selectedParentId) ||
        selectedParentId <= 0
      ) {
        return res.status(400).json({
          success: false,
          message: "Invalid parent_id",
        });
      }
    }

    // =====================================================
    // SEARCH
    // =====================================================

    const searchTerm =
      typeof search === "string"
        ? search.trim()
        : "";

    // =====================================================
    // CASE 1
    // NO PARENT SELECTED
    //
    // Example:
    // role_id=2
    //
    // Returns all CNF users.
    //
    // With search:
    // role_id=2&search=rahul
    //
    // Returns only matching CNF users.
    // =====================================================

    if (selectedParentId === null) {
      let whereClause = `
        WHERE role_id = ?
      `;

      const queryParams = [
        requestedRoleId,
      ];

      // ===================================================
      // ADD SEARCH CONDITION
      // ===================================================

      if (searchTerm) {
        whereClause += `
          AND (
            name LIKE ?
            OR email LIKE ?
            OR phone LIKE ?
            OR organization_name LIKE ?
          )
        `;

        const searchValue =
          `%${searchTerm}%`;

        queryParams.push(
          searchValue,
          searchValue,
          searchValue,
          searchValue
        );
      }

      // ===================================================
      // FETCH USERS
      // ===================================================

      const [rows] = await db.query(
        `
        SELECT
          id,
          organization_name,
          name,
          email,
          phone,
          role_id,
          parent_id,
          created_by,

          parent_admin_disabled,
          parent_cnf_disabled,
          parent_super_distributor_disabled,
          parent_distributor_disabled,
          parent_fos_disabled,
          parent_retailer_disabled,
          parent_sub_retailer_disabled,
          parent_employee_disabled,
          parent_staff_disabled

        FROM users

        ${whereClause}

        ORDER BY name ASC
        `,
        queryParams
      );

      // ===================================================
      // REMOVE DISABLED USERS
      // ===================================================

      const filteredRows = rows.filter((user) => {
        if (!disabledField) {
          return true;
        }

        return Number(
          user[disabledField] ?? 0
        ) !== 1;
      });

      // ===================================================
      // RESPONSE
      // ===================================================

      return res.status(200).json({
        success: true,

        create_role_id:
          requestedRoleId,

        parent_id:
          null,

        current_role_id:
          requestedRoleId,

        current_role_name:
          getRoleName(requestedRoleId),

        search:
          searchTerm,

        total:
          filteredRows.length,

        data:
          filteredRows,
      });
    }

    // =====================================================
    // CASE 2
    // PARENT SELECTED
    // =====================================================

    const [parentRows] = await db.query(
      `
      SELECT
        id,
        organization_name,
        name,
        email,
        phone,
        role_id,
        parent_id,
        created_by,

        parent_admin_disabled,
        parent_cnf_disabled,
        parent_super_distributor_disabled,
        parent_distributor_disabled,
        parent_fos_disabled,
        parent_retailer_disabled,
        parent_sub_retailer_disabled,
        parent_employee_disabled,
        parent_staff_disabled

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

    const selectedParent =
      parentRows[0];

    const parentRoleId =
      Number(selectedParent.role_id);

    // =====================================================
    // CHECK WHETHER SELECTED PARENT CAN BE PARENT
    // =====================================================

    if (
      requestedRoleId <= parentRoleId
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Selected parent must be a higher level role",
      });
    }

    // =====================================================
    // CHECK PARENT DISABLED THIS ROLE
    // =====================================================

    const parentDisabledField =
      disabledFieldMap[requestedRoleId];

    const isDisabledByParent =
      parentDisabledField &&
      Number(
        selectedParent[
          parentDisabledField
        ] ?? 0
      ) === 1;

    if (isDisabledByParent) {
      return res.status(200).json({
        success: true,

        create_role_id:
          requestedRoleId,

        parent_id:
          selectedParentId,

        parent_role_id:
          parentRoleId,

        current_role_id:
          requestedRoleId,

        current_role_name:
          getRoleName(requestedRoleId),

        search:
          searchTerm,

        total:
          0,

        data: [],

        message:
          `${getRoleName(
            parentRoleId
          )} has disabled ${getRoleName(
            requestedRoleId
          )}`,
      });
    }

    // =====================================================
    // FETCH REQUESTED ROLE UNDER SELECTED PARENT
    // =====================================================

    let whereClause = `
      WHERE role_id = ?
      AND parent_id = ?
    `;

    const queryParams = [
      requestedRoleId,
      selectedParentId,
    ];

    // =====================================================
    // ADD SEARCH CONDITION
    // =====================================================

    if (searchTerm) {
      whereClause += `
        AND (
          name LIKE ?
          OR email LIKE ?
          OR phone LIKE ?
          OR organization_name LIKE ?
        )
      `;

      const searchValue =
        `%${searchTerm}%`;

      queryParams.push(
        searchValue,
        searchValue,
        searchValue,
        searchValue
      );
    }

    // =====================================================
    // FETCH USERS
    // =====================================================

    const [rows] = await db.query(
      `
      SELECT
        id,
        organization_name,
        name,
        email,
        phone,
        role_id,
        parent_id,
        created_by,

        parent_admin_disabled,
        parent_cnf_disabled,
        parent_super_distributor_disabled,
        parent_distributor_disabled,
        parent_fos_disabled,
        parent_retailer_disabled,
        parent_sub_retailer_disabled,
        parent_employee_disabled,
        parent_staff_disabled

      FROM users

      ${whereClause}

      ORDER BY name ASC
      `,
      queryParams
    );

    // =====================================================
    // REMOVE DISABLED USERS
    // =====================================================

    const filteredRows = rows.filter((user) => {
      if (!disabledField) {
        return true;
      }

      return Number(
        user[disabledField] ?? 0
      ) !== 1;
    });

    // =====================================================
    // RESPONSE
    // =====================================================

    return res.status(200).json({
      success: true,

      create_role_id:
        requestedRoleId,

      parent_id:
        selectedParentId,

      parent_role_id:
        parentRoleId,

      current_role_id:
        requestedRoleId,

      current_role_name:
        getRoleName(requestedRoleId),

      search:
        searchTerm,

      total:
        filteredRows.length,

      data:
        filteredRows,
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

      // =========================================
      // ONLY ONE PARENT ID
      // =========================================
      parent_id,

      // =========================================
      // DEVICE PERMISSIONS
      // =========================================
      new_device,
      old_device,
      supreme_device,
      pro_star,
      lite,
      google_tv,
      supreme_lock,

      // =========================================
      // PASSWORD
      // =========================================
      password,
    } = req.body;

    // =========================================
    // VALIDATE USER ID
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
    // CHECK USER EXISTS
    // =========================================
    const [existingUser] = await db.query(
      `
      SELECT id, role_id
      FROM users
      WHERE id = ?
      LIMIT 1
      `,
      [userId]
    );

    if (!existingUser || existingUser.length === 0) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // =========================================
    // NORMALIZE PARENT ID
    // =========================================
    const normalizedParentId =
      parent_id !== null &&
      parent_id !== undefined &&
      parent_id !== ""
        ? Number(parent_id)
        : null;

    // =========================================
    // BUILD UPDATE QUERY
    // =========================================

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

    // =========================================
    // PASSWORD ONLY IF PROVIDED
    // =========================================
    if (
      password !== undefined &&
      password !== null &&
      password !== ""
    ) {
      updateQuery += `
        , password = ?
      `;

      updateValues.push(password);
    }

    // =========================================
    // WHERE
    // =========================================
    updateQuery += `
      WHERE id = ?
    `;

    updateValues.push(userId);

    // =========================================
    // UPDATE USER
    // =========================================
    const [result] = await db.query(
      updateQuery,
      updateValues
    );

    // =========================================
    // CHECK UPDATE
    // =========================================
    if (result.affectedRows === 0) {
      return res.status(400).json({
        success: false,
        message: "No changes made",
      });
    }

    // =========================================
    // GET UPDATED USER
    // IMPORTANT:
    // PASSWORD SELECT NAHI KARNA
    // =========================================
    const [updatedUser] = await db.query(
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
    // SUCCESS
    // =========================================
    return res.status(200).json({
      success: true,
      message: "Staff data updated successfully",
      data: updatedUser[0],
    });

  } catch (error) {
    console.error(
      "UPDATE STAFF ERROR:",
      error
    );

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

// export const getModules = async (req, res) => {
//   try {
//     // ==========================================
//     // GET MASTER ADMIN MODULES
//     // ==========================================

//     const [rows] = await db.query(
//       `
//       SELECT modules
//       FROM users
//       WHERE role_id = 0
//       LIMIT 1
//       `
//     );

//     // ==========================================
//     // MASTER ADMIN NOT FOUND
//     // ==========================================

//     if (!rows.length) {
//       return res.json({
//         success: true,
//         modules: [],
//       });
//     }

//     // ==========================================
//     // GET MODULES
//     // ==========================================

//     let modules = [];

//     if (rows[0].modules) {
//       modules =
//         typeof rows[0].modules === "string"
//           ? JSON.parse(rows[0].modules)
//           : rows[0].modules;
//     }

//     // ==========================================
//     // SAFETY CHECK
//     // ==========================================

//     if (!Array.isArray(modules)) {
//       modules = [];
//     }

//     // ==========================================
//     // RESPONSE
//     // ==========================================

//     return res.json({
//       success: true,
//       modules,
//     });

//   } catch (error) {
//     console.error("Get Modules Error:", error);

//     return res.status(500).json({
//       success: false,
//       message: "Internal server error",
//     });
//   }
// };

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

    // =================================================
    // ROLE CHECK
    // =================================================

    if (
      Number(req.user?.role_id) !== 0
    ) {

      return res.status(403).json({

        success: false,

        message:
          "Only Master Admin can update module",

      });

    }


    // =================================================
    // GET FORM DATA
    // =================================================

    const {
      oldModule,
      newModule,
      newSequence,
      status,
    } = req.body;


    // =================================================
    // OLD MODULE REQUIRED
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


    // =================================================
    // CHECK NEW MODULE
    // =================================================

    const hasNewModule =
      typeof newModule === "string" &&
      newModule.trim() !== "";


    // =================================================
    // CHECK NEW SEQUENCE
    // =================================================

    const hasNewSequence =
      newSequence !== undefined &&
      newSequence !== null &&
      String(newSequence).trim() !== "";


    // =================================================
    // CHECK NEW STATUS
    // =================================================

    const hasNewStatus =
      status !== undefined &&
      status !== null &&
      String(status).trim() !== "";


    // =================================================
    // CHECK NEW ICON
    // =================================================

    const hasNewIcon =
      !!req.file;


    // =================================================
    // AT LEAST ONE FIELD REQUIRED
    // =================================================

    if (
      !hasNewModule &&
      !hasNewSequence &&
      !hasNewStatus &&
      !hasNewIcon
    ) {

      return res.status(400).json({

        success: false,

        message:
          "At least one field is required to update",

      });

    }


    // =================================================
    // VALIDATE SEQUENCE
    // =================================================

    let sequence = null;


    if (hasNewSequence) {

      sequence =
        Number(newSequence);


      if (
        !Number.isInteger(sequence) ||
        sequence < 1
      ) {

        return res.status(400).json({

          success: false,

          message:
            "Valid sequence number is required",

        });

      }

    }


    // =================================================
    // VALIDATE STATUS
    // 0 = INACTIVE / HIDE
    // 1 = ACTIVE / SHOW
    // =================================================

    let moduleStatus = null;


    if (hasNewStatus) {

      moduleStatus =
        Number(status);


      if (
        moduleStatus !== 0 &&
        moduleStatus !== 1
      ) {

        return res.status(400).json({

          success: false,

          message:
            "Status must be either 0 or 1",

        });

      }

    }


    // =================================================
    // CLEAN MODULE NAMES
    // =================================================

    const oldModuleName =
      oldModule
        .trim()
        .toLowerCase();


    const newModuleName =
      hasNewModule
        ? newModule
            .trim()
            .toLowerCase()
        : null;


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


    // =================================================
    // MASTER ADMIN NOT FOUND
    // =================================================

    if (!rows.length) {

      // Delete uploaded icon

      if (req.file) {

        const uploadedFilePath =
          path.join(
            uploadDir,
            req.file.filename
          );


        if (
          fs.existsSync(
            uploadedFilePath
          )
        ) {

          fs.unlinkSync(
            uploadedFilePath
          );

        }

      }


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

    let modules =
      masterAdmin.modules;


    if (!modules) {

      modules = [];

    }
    else if (
      typeof modules === "string"
    ) {

      try {

        modules =
          JSON.parse(modules);

      }
      catch (error) {

        console.error(
          "MODULE JSON PARSE ERROR:",
          error
        );


        // Delete uploaded icon

        if (req.file) {

          const uploadedFilePath =
            path.join(
              uploadDir,
              req.file.filename
            );


          if (
            fs.existsSync(
              uploadedFilePath
            )
          ) {

            fs.unlinkSync(
              uploadedFilePath
            );

          }

        }


        return res.status(500).json({

          success: false,

          message:
            "Invalid modules data",

        });

      }

    }


    // =================================================
    // ARRAY CHECK
    // =================================================

    if (!Array.isArray(modules)) {

      return res.status(500).json({

        success: false,

        message:
          "Modules data must be an array",

      });

    }


    // =================================================
    // CONVERT OLD MODULE FORMAT
    //
    // OLD:
    // {
    //   name: "cnf",
    //   icon: null
    // }
    //
    // NEW:
    // {
    //   name: "cnf",
    //   icon: null,
    //   sequence: 1,
    //   status: 1
    // }
    // =================================================

    modules =
      modules.map(
        (item, index) => {

          // -------------------------------------------
          // STRING FORMAT
          // -------------------------------------------

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


          // -------------------------------------------
          // OBJECT FORMAT
          // -------------------------------------------

          return {

            name:
              item?.name ||
              "",

            icon:
              item?.icon ||
              null,

            sequence:
              Number(
                item?.sequence ??
                index + 1
              ),

            status:
              Number(
                item?.status ??
                1
              ) === 0
                ? 0
                : 1,

          };

        }
      );


    // =================================================
    // FIND MODULE
    // =================================================

    const moduleIndex =
      modules.findIndex(
        (item) => {

          return (
            String(
              item?.name ||
              ""
            )
              .trim()
              .toLowerCase() ===
            oldModuleName
          );

        }
      );


    // =================================================
    // MODULE NOT FOUND
    // =================================================

    if (
      moduleIndex === -1
    ) {

      // Delete uploaded icon

      if (req.file) {

        const uploadedFilePath =
          path.join(
            uploadDir,
            req.file.filename
          );


        if (
          fs.existsSync(
            uploadedFilePath
          )
        ) {

          fs.unlinkSync(
            uploadedFilePath
          );

        }

      }


      return res.status(404).json({

        success: false,

        message:
          `Old module "${oldModule}" not found`,

      });

    }


    // =================================================
    // CURRENT MODULE
    // =================================================

    const currentModule =
      modules[moduleIndex];


    // =================================================
    // DUPLICATE MODULE NAME
    // =================================================

    if (hasNewModule) {

      const duplicateModule =
        modules.some(
          (item, index) => {

            if (
              index === moduleIndex
            ) {

              return false;

            }


            return (
              String(
                item?.name ||
                ""
              )
                .trim()
                .toLowerCase() ===
              newModuleName
            );

          }
        );


      if (duplicateModule) {

        // Delete uploaded icon

        if (req.file) {

          const uploadedFilePath =
            path.join(
              uploadDir,
              req.file.filename
            );


          if (
            fs.existsSync(
              uploadedFilePath
            )
          ) {

            fs.unlinkSync(
              uploadedFilePath
            );

          }

        }


        return res.status(409).json({

          success: false,

          message:
            `Module "${newModule}" already exists`,

        });

      }

    }


    // =================================================
    // DUPLICATE SEQUENCE
    // =================================================

    if (hasNewSequence) {

      const duplicateSequence =
        modules.some(
          (item, index) => {

            if (
              index === moduleIndex
            ) {

              return false;

            }


            return (
              Number(
                item?.sequence
              ) ===
              sequence
            );

          }
        );


      if (duplicateSequence) {

        // Delete uploaded icon

        if (req.file) {

          const uploadedFilePath =
            path.join(
              uploadDir,
              req.file.filename
            );


          if (
            fs.existsSync(
              uploadedFilePath
            )
          ) {

            fs.unlinkSync(
              uploadedFilePath
            );

          }

        }


        return res.status(422).json({

          success: false,

          message:
            `Sequence ${sequence} is already used`,

        });

      }

    }


    // =================================================
    // OLD VALUES
    // =================================================

    const oldIcon =
      currentModule?.icon ||
      null;


    // =================================================
    // FINAL NAME
    // =================================================

    const finalName =
      hasNewModule
        ? newModuleName
        : currentModule?.name || "";


    // =================================================
    // FINAL SEQUENCE
    // =================================================

    const finalSequence =
      hasNewSequence
        ? sequence
        : Number(
            currentModule?.sequence ||
            moduleIndex + 1
          );


    // =================================================
    // FINAL STATUS
    // =================================================

    const finalStatus =
      hasNewStatus
        ? moduleStatus
        : Number(
            currentModule?.status ?? 1
          ) === 0
            ? 0
            : 1;


    // =================================================
    // FINAL ICON
    // =================================================

    let finalIcon =
      currentModule?.icon ||
      null;


    // =================================================
    // UPDATE ICON ONLY IF PROVIDED
    // =================================================

    if (hasNewIcon) {

      finalIcon =
        `/uploads/modules/${req.file.filename}`;

    }


    // =================================================
    // UPDATE MODULE
    // =================================================

    modules[moduleIndex] = {

      name:
        finalName,

      icon:
        finalIcon,

      sequence:
        finalSequence,

      status:
        finalStatus,

    };


    // =================================================
    // SORT BY SEQUENCE
    // =================================================

    modules.sort(
      (a, b) =>
        Number(a.sequence) -
        Number(b.sequence)
    );


    // =================================================
    // UPDATE DATABASE
    // =================================================

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


    // =================================================
    // DELETE OLD ICON
    // ONLY WHEN NEW ICON IS UPLOADED
    // =================================================

    if (
      hasNewIcon &&
      oldIcon &&
      oldIcon !== finalIcon
    ) {

      try {

        const oldIconPath =
          path.join(
            process.cwd(),
            oldIcon.replace(
              /^\/+/,
              ""
            )
          );


        if (
          fs.existsSync(
            oldIconPath
          )
        ) {

          fs.unlinkSync(
            oldIconPath
          );

        }

      }
      catch (iconDeleteError) {

        console.error(
          "OLD ICON DELETE ERROR:",
          iconDeleteError
        );

      }

    }


    // =================================================
    // SUCCESS
    // =================================================

    return res.status(200).json({

      success: true,

      message:
        "Module updated successfully",

      module: {

        oldModule:
          oldModuleName,

        newModule:
          finalName,

        icon:
          finalIcon,

        sequence:
          finalSequence,

        status:
          finalStatus,

      },

      modules,

    });

  }
  catch (error) {

    console.error(
      "UPDATE MODULE ERROR:",
      error
    );


    // =================================================
    // DELETE NEW ICON ON ERROR
    // =================================================

    if (req.file) {

      try {

        const filePath =
          path.join(
            uploadDir,
            req.file.filename
          );


        if (
          fs.existsSync(filePath)
        ) {

          fs.unlinkSync(
            filePath
          );

        }

      }
      catch (fileError) {

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