import db from "../config/db.js";
import pool from "../config/db.js";

export const findUserByEmail = async(email)=>{

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
    // =========================
    // BASIC DETAILS
    // =========================
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

    // =========================
    // HIERARCHY
    // =========================
    parent_admin_id = null,
    parent_cnf_id = null,
    parent_super_distributor_id = null,
    parent_distributor_id = null,
    parent_fos_id = null,
    parent_retailer_id = null,
    parent_staff_id = null,

    // =========================
    // DEVICE PERMISSIONS
    // =========================
    new_device = 0,
    old_device = 0,
    supreme_device = 0,
    pro_star = 0,
    lite = 0,
    google_tv = 0,
    supreme_lock = 0,

  } = data;


  // =========================
  // INSERT USER
  // =========================

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
    )
    VALUES
    (
      ?, ?, ?, ?, ?,
      ?, ?, ?, ?,
      ?, ?,

      ?, ?, ?, ?, ?,
      ?, ?,

      ?, ?, ?, ?, ?,
      ?, ?
    )
  `;


  const values = [

    // =========================
    // BASIC DETAILS
    // =========================

    organization_name,
    name,
    email,
    phone,
    password,
    company_address,
    country,
    state,
    city,
    Number(role_id),
    Number(created_by),


    // =========================
    // HIERARCHY
    // =========================

    parent_admin_id
      ? Number(parent_admin_id)
      : null,

    parent_cnf_id
      ? Number(parent_cnf_id)
      : null,

    parent_super_distributor_id
      ? Number(parent_super_distributor_id)
      : null,

    parent_distributor_id
      ? Number(parent_distributor_id)
      : null,

    parent_fos_id
      ? Number(parent_fos_id)
      : null,

    parent_retailer_id
      ? Number(parent_retailer_id)
      : null,

    parent_staff_id
      ? Number(parent_staff_id)
      : null,


    // =========================
    // DEVICE PERMISSIONS
    // =========================

    Number(new_device),
    Number(old_device),
    Number(supreme_device),
    Number(pro_star),
    Number(lite),
    Number(google_tv),
    Number(supreme_lock)

  ];


  const [result] = await db.query(sql, values);


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
      c.role_id AS created_by_role_id

    FROM users u

    LEFT JOIN users c
      ON u.created_by = c.id

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

    ORDER BY u.id ASC

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



