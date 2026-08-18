import db from "../config/db.js";
import pool from "../config/db.js";

export const findUserByEmail = async (email) => {
  const [rows] = await db.query(
    "SELECT * FROM users WHERE email=?",
    [email]
  );

  return rows[0];
};

export const findUserById = async (id) => {

  const [rows] = await db.query(

    `
    SELECT 
    id,
    name,
    role_id
    FROM users
    WHERE id=?
    `,
    [id]

  );


  return rows[0];

};

export const createUser = async (data) => {

  const {

    // ========================================
    // BASIC DETAILS
    // ========================================

    organization_name,

    name,

    email,

    phone,

    password,

    company_address,

    country,

    state,

    city,


    // ========================================
    // ROLE
    // ========================================

    role_id,

    created_by,


    // ========================================
    // PARENT
    // ========================================

    parent_id = null,


    // ========================================
    // DEVICE PERMISSIONS
    // ========================================

    new_device = 0,

    old_device = 0,

    supreme_device = 0,

    pro_star = 0,

    lite = 0,

    google_tv = 0,

    supreme_lock = 0,

  } = data;


  // ==========================================
  // INSERT QUERY
  // ==========================================

  const sql = `

    INSERT INTO users
    (
      organization_name,
      name,
      email,
      phone,
      password,

      company_address,
      country,
      state,
      city,

      role_id,
      created_by,
      parent_id,

      new_device,
      old_device,
      supreme_device,
      pro_star,
      lite,
      google_tv,
      supreme_lock
    )

    VALUES
    (
      ?, ?, ?, ?, ?,

      ?, ?, ?, ?,

      ?, ?, ?,

      ?, ?, ?, ?, ?,
      ?, ?
    )

  `;


  // ==========================================
  // VALUES
  // ==========================================

  const values = [

    // BASIC

    organization_name,

    name,

    email,

    phone,

    password,


    // LOCATION

    company_address,

    country,

    state,

    city,


    // ROLE

    Number(role_id),


    // CREATOR

    Number(created_by),


    // PARENT

    parent_id !== null &&
    parent_id !== undefined
      ? Number(parent_id)
      : null,


    // ========================================
    // DEVICES
    // ========================================

    Number(new_device ?? 0),

    Number(old_device ?? 0),

    Number(supreme_device ?? 0),

    Number(pro_star ?? 0),

    Number(lite ?? 0),

    Number(google_tv ?? 0),

    Number(supreme_lock ?? 0),

  ];


  // ==========================================
  // DATABASE INSERT
  // ==========================================

  const [result] =
    await db.query(
      sql,
      values
    );


  // ==========================================
  // RETURN NEW USER ID
  // ==========================================

  return result.insertId;
};
// Get All Users
export const getAllUsers = async (
  limit,
  offset,
  role_id
) => {
  let query = `
    SELECT

      u.id,
      u.organization_name,
      u.name,
      u.email,
      u.phone,
      u.company_address,
      u.country,
      u.state,
      u.city,

      u.role_id,
      u.created_by,
      u.created_at,

      -- =========================
      -- HIERARCHY
      -- =========================

      u.parent_admin_id,
      u.parent_cnf_id,
      u.parent_super_distributor_id,
      u.parent_distributor_id,
      u.parent_fos_id,
      u.parent_retailer_id,
      u.parent_staff_id,

      -- =========================
      -- DEVICE PERMISSIONS
      -- =========================

      u.new_device,
      u.old_device,
      u.supreme_device,
      u.pro_star,
      u.lite,
      u.google_tv,
      u.supreme_lock,

      -- =========================
      -- CREATOR DETAILS
      -- =========================

      c.name AS created_by_name,
      c.organization_name AS created_by_company,
      c.role_id AS created_by_role_id,

      -- =========================
      -- PARENT DETAILS
      -- =========================

      p.name AS parent_name,
      p.organization_name AS parent_company,
      p.role_id AS parent_role_id,
      p.id AS parent_id

    FROM users u

    -- =========================
    -- CREATOR
    -- =========================

    LEFT JOIN users c
      ON u.created_by = c.id

    -- =========================
    -- PARENT
    -- =========================

    LEFT JOIN users p
      ON p.id = CASE

        -- Admin ka parent Master Admin hoga
        WHEN u.role_id = 1
          THEN u.created_by

        -- CNF ka parent Admin
        WHEN u.role_id = 2
          THEN u.parent_admin_id

        -- Super Distributor ka parent CNF
        WHEN u.role_id = 3
          THEN u.parent_cnf_id

        -- Distributor ka parent Super Distributor
        WHEN u.role_id = 4
          THEN u.parent_super_distributor_id

        -- FOS ka parent Distributor
        WHEN u.role_id = 5
          THEN u.parent_distributor_id

        -- Retailer ka parent:
        -- FOS available ho to FOS
        WHEN u.role_id = 6
          THEN COALESCE(
            u.parent_fos_id,
            u.parent_distributor_id
          )

        -- Employee ka parent Retailer
        WHEN u.role_id = 7
          THEN u.parent_retailer_id

        -- Staff ka parent
        WHEN u.role_id = 8
          THEN u.parent_staff_id

        ELSE NULL

      END
  `;

  let params = [];

  // =========================
  // ROLE FILTER
  // =========================

  if (role_id) {
    query += ` WHERE u.role_id = ? `;
    params.push(role_id);
  }

  // =========================
  // PAGINATION
  // =========================

  query += `
    ORDER BY u.id DESC
    LIMIT ? OFFSET ?
  `;

  params.push(
    Number(limit),
    Number(offset)
  );

  // =========================
  // GET USERS
  // =========================

  const [rows] = await db.query(
    query,
    params
  );

  // =========================
  // COUNT
  // =========================

  let countQuery = `
    SELECT COUNT(*) AS total
    FROM users u
  `;

  let countParams = [];

  if (role_id) {
    countQuery += ` WHERE u.role_id = ? `;
    countParams.push(role_id);
  }

  const [count] = await db.query(
    countQuery,
    countParams
  );

  return {
    users: rows,
    total: count[0].total
  };
};

//get getAllHierarchyUsers 
export const getAllHierarchyUsers = async () => {

    const [rows] = await db.query(`
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
            created_by,
            created_at,

            new_device,
            old_device,
            supreme_device,
            pro_star,
            lite,
            google_tv,
            supreme_lock

        FROM users
        ORDER BY id ASC
    `);

    return rows;

};



