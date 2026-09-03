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
    parent_id = null,
    new_device = 0,
    old_device = 0,
    supreme_device = 0,
    pro_star = 0,
    lite = 0,
    google_tv = 0,
    supreme_lock = 0,
  } = data;

  const sql = `
    INSERT INTO users (
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
    VALUES (
      ?, ?, ?, ?, ?,
      ?, ?, ?, ?,
      ?, ?, ?,
      ?, ?, ?, ?, ?,
      ?, ?
    )
  `;

  const values = [
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
    parent_id !== null && parent_id !== undefined
      ? Number(parent_id)
      : null,
    Number(new_device ?? 0),
    Number(old_device ?? 0),
    Number(supreme_device ?? 0),
    Number(pro_star ?? 0),
    Number(lite ?? 0),
    Number(google_tv ?? 0),
    Number(supreme_lock ?? 0),
  ];

  const [result] = await db.query(sql, values);

  return result.insertId;
};
// Get All Users
export const getAllUsers = async (
  limit,
  offset,
  role_id = null,
  loggedInUserId = null,
  loggedInRoleId = null,
  search = null,
  country = null,
  state = null,
  city = null,
  status = null
) => {
  try {
    // =====================================================
    // BASIC VALUES
    // =====================================================

    limit = Number(limit) || 10;
    offset = Number(offset) || 0;

    loggedInUserId = Number(
      loggedInUserId
    );

    loggedInRoleId = Number(
      loggedInRoleId
    );

    // =====================================================
    // VALIDATION
    // =====================================================

    if (
      !Number.isInteger(loggedInUserId) ||
      loggedInUserId <= 0
    ) {
      throw new Error(
        "Logged-in user ID is required"
      );
    }

    if (!Number.isInteger(loggedInRoleId)) {
      throw new Error(
        "Logged-in user role ID is required"
      );
    }

    // =====================================================
    // NORMALIZE
    // =====================================================

    search =
      search !== null &&
      search !== undefined &&
      String(search).trim() !== ""
        ? String(search).trim()
        : null;

    country =
      country !== null &&
      country !== undefined &&
      String(country).trim() !== ""
        ? String(country).trim()
        : null;

    state =
      state !== null &&
      state !== undefined &&
      String(state).trim() !== ""
        ? String(state).trim()
        : null;

    city =
      city !== null &&
      city !== undefined &&
      String(city).trim() !== ""
        ? String(city).trim()
        : null;

    // =====================================================
    // MASTER ADMIN + ADMIN
    // =====================================================

    if (
      loggedInRoleId === 0 ||
      loggedInRoleId === 1
    ) {
      let whereCondition = `
        WHERE 1 = 1
      `;

      const queryParams = [];

      // ===================================================
      // ROLE FILTER
      // ===================================================

      if (
        role_id !== null &&
        role_id !== ""
      ) {
        whereCondition += `
          AND u.role_id = ?
        `;

        queryParams.push(
          Number(role_id)
        );
      }

      // ===================================================
      // SEARCH
      // Name + Organization + Role
      // ===================================================

      if (search !== null) {
        whereCondition += `
          AND (
            LOWER(COALESCE(u.name, '')) LIKE LOWER(?)
            OR LOWER(COALESCE(u.organization_name, '')) LIKE LOWER(?)
            OR LOWER(
              CASE u.role_id
                WHEN 0 THEN 'Master Admin'
                WHEN 1 THEN 'Admin'
                WHEN 2 THEN 'CNF'
                WHEN 3 THEN 'Super Distributor'
                WHEN 4 THEN 'Distributor'
                WHEN 5 THEN 'FOS'
                WHEN 6 THEN 'Retailer'
                WHEN 7 THEN 'Sub Retailer'
                WHEN 8 THEN 'Employee'
                WHEN 9 THEN 'Staff'
                ELSE ''
              END
            ) LIKE LOWER(?)
          )
        `;

        const searchValue = `%${search}%`;

        queryParams.push(
          searchValue,
          searchValue,
          searchValue
        );
      }

      // ===================================================
      // COUNTRY
      // Partial Search
      // ===================================================

      if (country !== null) {
        whereCondition += `
          AND LOWER(TRIM(COALESCE(u.country, '')))
              LIKE LOWER(?)
        `;

        queryParams.push(
          `%${country}%`
        );
      }

      // ===================================================
      // STATE
      // Partial Search
      // ===================================================

      if (state !== null) {
        whereCondition += `
          AND LOWER(TRIM(COALESCE(u.state, '')))
              LIKE LOWER(?)
        `;

        queryParams.push(
          `%${state}%`
        );
      }

      // ===================================================
      // CITY
      // Partial Search
      // ===================================================

      if (city !== null) {
        whereCondition += `
          AND LOWER(TRIM(COALESCE(u.city, '')))
              LIKE LOWER(?)
        `;

        queryParams.push(
          `%${city}%`
        );
      }

      // ===================================================
      // STATUS
      // ===================================================

      if (
        status !== null &&
        status !== ""
      ) {
        whereCondition += `
          AND u.userStatus = ?
        `;

        queryParams.push(
          Number(status)
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

      const [users] = await db.query(
        sql,
        queryParams
      );

      // ===================================================
      // COUNT QUERY
      // ===================================================

      let countWhereCondition = `
        WHERE 1 = 1
      `;

      const countParams = [];

      // ROLE
      if (
        role_id !== null &&
        role_id !== ""
      ) {
        countWhereCondition += `
          AND u.role_id = ?
        `;

        countParams.push(
          Number(role_id)
        );
      }

      // SEARCH
      if (search !== null) {
        countWhereCondition += `
          AND (
            LOWER(COALESCE(u.name, '')) LIKE LOWER(?)
            OR LOWER(COALESCE(u.organization_name, '')) LIKE LOWER(?)
            OR LOWER(
              CASE u.role_id
                WHEN 0 THEN 'Master Admin'
                WHEN 1 THEN 'Admin'
                WHEN 2 THEN 'CNF'
                WHEN 3 THEN 'Super Distributor'
                WHEN 4 THEN 'Distributor'
                WHEN 5 THEN 'FOS'
                WHEN 6 THEN 'Retailer'
                WHEN 7 THEN 'Sub Retailer'
                WHEN 8 THEN 'Employee'
                WHEN 9 THEN 'Staff'
                ELSE ''
              END
            ) LIKE LOWER(?)
          )
        `;

        const searchValue = `%${search}%`;

        countParams.push(
          searchValue,
          searchValue,
          searchValue
        );
      }

      // COUNTRY
      if (country !== null) {
        countWhereCondition += `
          AND LOWER(TRIM(COALESCE(u.country, '')))
              LIKE LOWER(?)
        `;

        countParams.push(
          `%${country}%`
        );
      }

      // STATE
      if (state !== null) {
        countWhereCondition += `
          AND LOWER(TRIM(COALESCE(u.state, '')))
              LIKE LOWER(?)
        `;

        countParams.push(
          `%${state}%`
        );
      }

      // CITY
      if (city !== null) {
        countWhereCondition += `
          AND LOWER(TRIM(COALESCE(u.city, '')))
              LIKE LOWER(?)
        `;

        countParams.push(
          `%${city}%`
        );
      }

      // STATUS
      if (
        status !== null &&
        status !== ""
      ) {
        countWhereCondition += `
          AND u.userStatus = ?
        `;

        countParams.push(
          Number(status)
        );
      }

      const countSql = `
        SELECT COUNT(*) AS total
        FROM users u
        ${countWhereCondition}
      `;

      const [countResult] = await db.query(
        countSql,
        countParams
      );

      const total = Number(
        countResult?.[0]?.total || 0
      );

      return {
        users,
        total,
      };
    }

    // =====================================================
    // NON ADMIN USERS
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

      SELECT COUNT(*) AS total

      FROM users u

      INNER JOIN user_chain uc
        ON uc.id = u.id

      WHERE u.id != ?
    `;

    const countParams = [
      loggedInUserId,
      loggedInUserId,
    ];

    // ROLE
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

    // SEARCH
    if (search !== null) {
      countSql += `
        AND (
          LOWER(COALESCE(u.name, '')) LIKE LOWER(?)
          OR LOWER(COALESCE(u.organization_name, '')) LIKE LOWER(?)
          OR LOWER(
            CASE u.role_id
              WHEN 0 THEN 'Master Admin'
              WHEN 1 THEN 'Admin'
              WHEN 2 THEN 'CNF'
              WHEN 3 THEN 'Super Distributor'
              WHEN 4 THEN 'Distributor'
              WHEN 5 THEN 'FOS'
              WHEN 6 THEN 'Retailer'
              WHEN 7 THEN 'Sub Retailer'
              WHEN 8 THEN 'Employee'
              WHEN 9 THEN 'Staff'
              ELSE ''
            END
          ) LIKE LOWER(?)
        )
      `;

      const searchValue = `%${search}%`;

      countParams.push(
        searchValue,
        searchValue,
        searchValue
      );
    }

    // COUNTRY
    if (country !== null) {
      countSql += `
        AND LOWER(TRIM(COALESCE(u.country, '')))
            LIKE LOWER(?)
      `;

      countParams.push(
        `%${country}%`
      );
    }

    // STATE
    if (state !== null) {
      countSql += `
        AND LOWER(TRIM(COALESCE(u.state, '')))
            LIKE LOWER(?)
      `;

      countParams.push(
        `%${state}%`
      );
    }

    // CITY
    if (city !== null) {
      countSql += `
        AND LOWER(TRIM(COALESCE(u.city, '')))
            LIKE LOWER(?)
      `;

      countParams.push(
        `%${city}%`
      );
    }

    // STATUS
    if (
      status !== null &&
      status !== ""
    ) {
      countSql += `
        AND u.userStatus = ?
      `;

      countParams.push(
        Number(status)
      );
    }

    const [countResult] = await db.query(
      countSql,
      countParams
    );

    const total = Number(
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

    // ROLE
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

    // SEARCH
    if (search !== null) {
      sql += `
        AND (
          LOWER(COALESCE(u.name, '')) LIKE LOWER(?)
          OR LOWER(COALESCE(u.organization_name, '')) LIKE LOWER(?)
          OR LOWER(
            CASE u.role_id
              WHEN 0 THEN 'Master Admin'
              WHEN 1 THEN 'Admin'
              WHEN 2 THEN 'CNF'
              WHEN 3 THEN 'Super Distributor'
              WHEN 4 THEN 'Distributor'
              WHEN 5 THEN 'FOS'
              WHEN 6 THEN 'Retailer'
              WHEN 7 THEN 'Sub Retailer'
              WHEN 8 THEN 'Employee'
              WHEN 9 THEN 'Staff'
              ELSE ''
            END
          ) LIKE LOWER(?)
        )
      `;

      const searchValue = `%${search}%`;

      sqlParams.push(
        searchValue,
        searchValue,
        searchValue
      );
    }

    // COUNTRY
    if (country !== null) {
      sql += `
        AND LOWER(TRIM(COALESCE(u.country, '')))
            LIKE LOWER(?)
      `;

      sqlParams.push(
        `%${country}%`
      );
    }

    // STATE
    if (state !== null) {
      sql += `
        AND LOWER(TRIM(COALESCE(u.state, '')))
            LIKE LOWER(?)
      `;

      sqlParams.push(
        `%${state}%`
      );
    }

    // CITY
    if (city !== null) {
      sql += `
        AND LOWER(TRIM(COALESCE(u.city, '')))
            LIKE LOWER(?)
      `;

      sqlParams.push(
        `%${city}%`
      );
    }

    // STATUS
    if (
      status !== null &&
      status !== ""
    ) {
      sql += `
        AND u.userStatus = ?
      `;

      sqlParams.push(
        Number(status)
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
    // EXECUTE
    // =====================================================

    const [users] = await db.query(
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

    console.table(
      users.map((user) => ({
        id: user.id,
        name: user.name,
        organization_name:
          user.organization_name,
        role_id: user.role_id,
        country: user.country,
        state: user.state,
        city: user.city,
        parent_id: user.parent_id,
        created_by: user.created_by,
      }))
    );

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


