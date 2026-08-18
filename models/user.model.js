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
export const getAllUsers = async (limit, offset, role_id = null) => {
  try {
    // =====================================================
    // WHERE CONDITION
    // =====================================================

    let whereCondition = "";
    let queryParams = [];

    if (role_id !== null && role_id !== "") {
      whereCondition = `WHERE u.role_id = ?`;
      queryParams.push(Number(role_id));
    }

    // =====================================================
    // GET USERS
    // =====================================================

    const sql = `
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
        u.parent_id,

        -- ================================================
        -- PARENT DETAILS
        -- ================================================

        p.name AS parent_name,
        p.organization_name AS parent_organization_name,

        -- ================================================
        -- DEVICE PERMISSIONS
        -- ================================================

        u.new_device,
        u.old_device,
        u.supreme_device,
        u.pro_star,
        u.lite,
        u.google_tv,
        u.supreme_lock,

        u.created_at,
        u.updated_at

      FROM users u

      LEFT JOIN users p
        ON p.id = u.parent_id

      ${whereCondition}

      ORDER BY u.id DESC

      LIMIT ? OFFSET ?
    `;

    queryParams.push(Number(limit));
    queryParams.push(Number(offset));

    const [users] = await db.query(
      sql,
      queryParams
    );

    // =====================================================
    // TOTAL COUNT
    // =====================================================

    const countSql = `
      SELECT COUNT(*) AS total
      FROM users u
      ${whereCondition}
    `;

    const [countResult] = await db.query(
      countSql,
      role_id !== null && role_id !== ""
        ? [Number(role_id)]
        : []
    );

    return {
      users,
      total: Number(countResult[0].total),
    };

  } catch (error) {
    console.error(
      "Get All Users Model Error:",
      error
    );

    throw error;
  }
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



