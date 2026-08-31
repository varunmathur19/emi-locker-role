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

  const [result] =
    await db.query(
      sql,
      values
    );

  return result.insertId;
};
// Get All Users
export const getAllUsers = async (
  limit,
  offset,
  role_id = null,
  loggedInUserId = null,
  loggedInRoleId = null
) => {
  try {
    limit = Number(limit) || 10;
    offset = Number(offset) || 0;

    loggedInUserId = Number(loggedInUserId);
    loggedInRoleId = Number(loggedInRoleId);

    if (
      !Number.isInteger(loggedInUserId) ||
      loggedInUserId <= 0
    ) {
      throw new Error(
        "Logged-in user ID is required"
      );
    }

    if (
      !Number.isInteger(loggedInRoleId)
    ) {
      throw new Error(
        "Logged-in user role ID is required"
      );
    }

    console.log(
      "=============================================="
    );

    console.log(
      "GET ALL USERS MODEL"
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

    console.log(
      "Limit:",
      limit
    );

    console.log(
      "Offset:",
      offset
    );

    console.log(
      "=============================================="
    );

    // =====================================================
    // MASTER ADMIN + ADMIN
    // =====================================================
    //
    // MASTER ADMIN = 0
    // ADMIN = 1
    //
    // Dono ko complete users data milega.
    //
    // =====================================================

    if (
      loggedInRoleId === 0 ||
      loggedInRoleId === 1
    ) {
      let whereCondition = "";

      const queryParams = [];

      // ===================================================
      // ROLE FILTER
      // ===================================================

      if (
        role_id !== null &&
        role_id !== ""
      ) {
        whereCondition = `
          WHERE u.role_id = ?
        `;

        queryParams.push(
          Number(role_id)
        );
      }

      // ===================================================
      // USERS QUERY
      // ===================================================

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

          u.userStatus,

          CASE
            WHEN u.role_id = 1
              THEN creator.name
            ELSE parent.name
          END AS parent_name,

          CASE
            WHEN u.role_id = 1
              THEN creator.organization_name
            ELSE parent.organization_name
          END AS parent_organization_name,

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

        LEFT JOIN users parent
          ON parent.id = u.parent_id

        LEFT JOIN users creator
          ON creator.id = u.created_by

        ${whereCondition}

        ORDER BY u.id DESC

        LIMIT ? OFFSET ?
      `;

      queryParams.push(
        limit,
        offset
      );

      const [
        users
      ] = await db.query(
        sql,
        queryParams
      );

      // ===================================================
      // COUNT
      // ===================================================

      const countSql = `
        SELECT
          COUNT(*) AS total

        FROM users u

        ${whereCondition}
      `;

      const countParams =
        role_id !== null &&
        role_id !== ""
          ? [Number(role_id)]
          : [];

      const [
        countResult
      ] = await db.query(
        countSql,
        countParams
      );

      const total =
        Number(
          countResult?.[0]?.total || 0
        );

      console.log(
        "ADMIN / MASTER USERS:",
        users.length
      );

      console.log(
        "ADMIN / MASTER TOTAL:",
        total
      );

      return {
        users,
        total,
      };
    }

    // =====================================================
    // NON ADMIN USERS
    // =====================================================
    //
    // IMPORTANT:
    //
    // Yahan hierarchy parent_id ke according niklegi.
    //
    // Example:
    //
    // CNF
    //  id = 10
    //
    // Super Distributor
    //  id = 20
    //  parent_id = 10
    //
    // Distributor
    //  id = 30
    //  parent_id = 20
    //
    // FOS
    //  id = 40
    //  parent_id = 30
    //
    // Retailer
    //  id = 50
    //  parent_id = 40
    //
    // Agar CNF 10 login karega:
    //
    // 20, 30, 40, 50
    //
    // Agar Super 20 login karega:
    //
    // 30, 40, 50
    //
    // Doosre CNF/Super ki chain nahi aayegi.
    //
    // =====================================================

    // =====================================================
    // COUNT QUERY
    // =====================================================

    let countSql = `
      WITH RECURSIVE user_chain AS (

        SELECT
          u.id,
          u.parent_id,
          u.created_by,
          u.role_id

        FROM users u

        WHERE u.id = ?

        UNION ALL

        SELECT
          child.id,
          child.parent_id,
          child.created_by,
          child.role_id

        FROM users child

        INNER JOIN user_chain parent
          ON child.parent_id = parent.id
      )

      SELECT
        COUNT(*) AS total

      FROM users u

      INNER JOIN user_chain uc
        ON uc.id = u.id

      WHERE u.id != ?
    `;

    const countParams = [
      loggedInUserId,
      loggedInUserId,
    ];

    // =====================================================
    // ROLE FILTER
    // =====================================================

    if (
      role_id !== null &&
      role_id !== ""
    ) {
      countSql += `
        AND u.role_id = ?
      `;

      countParams.push(
        Number(role_id)
      );
    }

    // =====================================================
    // COUNT EXECUTION
    // =====================================================

    const [
      countResult
    ] = await db.query(
      countSql,
      countParams
    );

    const total =
      Number(
        countResult?.[0]?.total || 0
      );

    // =====================================================
    // USERS QUERY
    // =====================================================

    let sql = `
      WITH RECURSIVE user_chain AS (

        SELECT
          u.id,
          u.parent_id,
          u.created_by,
          u.role_id

        FROM users u

        WHERE u.id = ?

        UNION ALL

        SELECT
          child.id,
          child.parent_id,
          child.created_by,
          child.role_id

        FROM users child

        INNER JOIN user_chain parent
          ON child.parent_id = parent.id
      )

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

        u.userStatus,

        CASE
          WHEN u.role_id = 1
            THEN creator.name
          ELSE parent.name
        END AS parent_name,

        CASE
          WHEN u.role_id = 1
            THEN creator.organization_name
          ELSE parent.organization_name
        END AS parent_organization_name,

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

      INNER JOIN user_chain uc
        ON uc.id = u.id

      LEFT JOIN users parent
        ON parent.id = u.parent_id

      LEFT JOIN users creator
        ON creator.id = u.created_by

      WHERE u.id != ?
    `;

    const sqlParams = [
      loggedInUserId,
      loggedInUserId,
    ];

    // =====================================================
    // ROLE FILTER
    // =====================================================

    if (
      role_id !== null &&
      role_id !== ""
    ) {
      sql += `
        AND u.role_id = ?
      `;

      sqlParams.push(
        Number(role_id)
      );
    }

    // =====================================================
    // PAGINATION
    // =====================================================

    sql += `
      ORDER BY u.id DESC
      LIMIT ? OFFSET ?
    `;

    sqlParams.push(
      limit,
      offset
    );

    // =====================================================
    // EXECUTE USERS QUERY
    // =====================================================

    const [
      users
    ] = await db.query(
      sql,
      sqlParams
    );

    // =====================================================
    // DEBUG
    // =====================================================

    console.log(
      "NON ADMIN USERS FOUND:",
      users.length
    );

    console.log(
      "NON ADMIN TOTAL:",
      total
    );

    console.log(
      "USER DETAILS:"
    );

    console.table(
      users.map(
        (user) => ({
          id: user.id,
          name: user.name,
          role_id: user.role_id,
          parent_id: user.parent_id,
          created_by: user.created_by,
        })
      )
    );

    // =====================================================
    // RETURN
    // =====================================================

    return {
      users,
      total,
    };

  } catch (error) {

    console.error(
      "GET ALL USERS MODEL ERROR:",
      error
    );

    throw error;
  }
};

//get getAllHierarchyUsers 
export const getAllHierarchyUsers = async () => {
    try {
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
                parent_id,

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

    } catch (error) {
        console.error("Error fetching hierarchy users:", error);
        throw error;
    }
};


