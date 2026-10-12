import db from "../config/db.js";

// import pool from "../config/db.js";

export const findUserByEmail = async (email) => {
  return await db("users")
    .select("id", "name", "email", "password", "role_id","parent_id","role_permission_id",
    "userStatus",)
    .where("email", email)
    .first();
};

export const findUserById = async (id) => {
  return await db("users")
    .select("id", "name", "role_id")
    .where("id", id)
    //unique honi chahiye 
    .first();
};

//add-staff

export const createUser = async (data) => {
    const {
        organization_name,
        name,
        email,
        phone,
        password,
        transaction_pin,
        company_address,
        country,
        state,
        city,
        role_id,
        created_by,
        parent_id = null,
        role_permission_id = null,
        new_device = 0,
        old_device = 0,
        supreme_device = 0,
        pro_star = 0,
        lite = 0,
        google_tv = 0,
        supreme_lock = 0,
    } = data;

    const [userId] = await db("users").insert({
        organization_name:
            organization_name || null,
        name,
        email,
        phone,
        password,
        transaction_pin:
            transaction_pin || null,
        company_address:
            company_address || null,
        country:
            country || null,
        state:
            state || null,
        city:
            city || null,
        role_id:
            Number(role_id),

        role_permission_id:
            role_permission_id !== null &&
            role_permission_id !== undefined &&
            role_permission_id !== ""
                ? Number(role_permission_id)
                : null,

        created_by:
            Number(created_by),

        parent_id:
            parent_id !== null &&
            parent_id !== undefined &&
            parent_id !== ""
                ? Number(parent_id)
                : null,

        new_device:
            Number(new_device ?? 0),
        old_device:
            Number(old_device ?? 0),
        supreme_device:
            Number(supreme_device ?? 0),
        pro_star:
            Number(pro_star ?? 0),
        lite:
            Number(lite ?? 0),
        google_tv:
            Number(google_tv ?? 0),
        supreme_lock:
            Number(supreme_lock ?? 0),
    });

    return userId;
};


// Get All Users
const roleNameCase = db.raw(`
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
`);

const selectUserFields = [
    "u.id",
    "u.organization_name",
    "u.name",
    "u.email",
    "u.phone",
    "u.transaction_pin",
    "u.company_address",
    "u.country",
    "u.state",
    "u.city",
    "u.role_id",
    "u.created_by",
    "u.parent_id",
    "u.userStatus",
    "u.wallet_balance",
    "u.role_permission_id",

    "p.id as profile_id",
    "p.name as profile_name",
    "p.status as profile_status",

    db.raw(`
        CASE
            WHEN u.role_id = 1 THEN creator.name
            ELSE parent.name
        END AS parent_name
    `),

    db.raw(`
        CASE
            WHEN u.role_id = 1 THEN creator.organization_name
            ELSE parent.organization_name
        END AS parent_organization_name
    `),

    "u.new_device",
    "u.old_device",
    "u.supreme_device",
    "u.pro_star",
    "u.lite",
    "u.google_tv",
    "u.supreme_lock",
    "u.created_at",
    "u.updated_at",
];


const applyFilters = (
  query,
  {
    role_id,
    search,
    country,
    state,
    city,
    status,
  }
) => {
  if (role_id !== null && role_id !== "") {
    query.where("u.role_id", Number(role_id));
  }

  if (search !== null) {
    const searchValue = `%${search}%`;

    query.where(function () {
      this.whereRaw(
        "LOWER(COALESCE(u.name, '')) LIKE LOWER(?)",
        [searchValue]
      )
        .orWhereRaw(
          "LOWER(COALESCE(u.organization_name, '')) LIKE LOWER(?)",
          [searchValue]
        )
        .orWhereRaw(
          `LOWER(
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
          ) LIKE LOWER(?)`,
          [searchValue]
        );
    });
  }

  if (country !== null) {
    query.whereRaw(
      "LOWER(TRIM(COALESCE(u.country, ''))) LIKE LOWER(?)",
      [`%${country}%`]
    );
  }

  if (state !== null) {
    query.whereRaw(
      "LOWER(TRIM(COALESCE(u.state, ''))) LIKE LOWER(?)",
      [`%${state}%`]
    );
  }

  if (city !== null) {
    query.whereRaw(
      "LOWER(TRIM(COALESCE(u.city, ''))) LIKE LOWER(?)",
      [`%${city}%`]
    );
  }

  if (status !== null && status !== "") {
    query.where("u.userStatus", Number(status));
  }

  return query;
};

const buildConnectedUserChain = (startUserId) =>
  db.withRecursive(
    "user_chain",
    ["id"],
    (query) => {
      query
        .select("id")
        .from("users")
        .where("id", Number(startUserId))
        .unionAll((childQuery) => {
          childQuery
            .select("child.id")
            .from({ current: "user_chain" })
            .join({ child: "users" }, function () {
              this.on("child.parent_id", "=", "current.id")
                .orOn("child.created_by", "=", "current.id");
            });
        });
    }
  );


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
  status = null,
  staffRoleAccess = false
) => {
  try {
    limit = Math.max(Number(limit) || 10, 1);
    offset = Math.max(Number(offset) || 0, 0);

    loggedInUserId = Number(loggedInUserId);
    loggedInRoleId = Number(loggedInRoleId);

    if (
      !Number.isInteger(loggedInUserId) ||
      loggedInUserId <= 0
    ) {
      throw new Error("Logged-in user ID is required");
    }

    if (!Number.isInteger(loggedInRoleId)) {
      throw new Error("Logged-in user role ID is required");
    }

    // Normalize filters
    const normalizeFilter = (value) => {
      if (
        value === null ||
        value === undefined ||
        String(value).trim() === ""
      ) {
        return null;
      }

      return String(value).trim();
    };

    search = normalizeFilter(search);
    country = normalizeFilter(country);
    state = normalizeFilter(state);
    city = normalizeFilter(city);

    const filters = {
      role_id,
      search,
      country,
      state,
      city,
      status,
    };

    /*
     * MASTER ADMIN:
     * Role 0 can see all users.
     *
     * ADMIN AND OTHER ROLES:
     * Only users returned by the logged-in user's
     * connected hierarchy are visible.
     *
     * STAFF:
     * Existing permission validation remains in getUsers.
     */
    const canSeeAllUsers =
      loggedInRoleId === 0 ||
      loggedInRoleId === 1;

    // Keep staff permission access restricted.
    if (
      loggedInRoleId === 9 &&
      !staffRoleAccess
    ) {
      throw new Error(
        "Staff is not authorized to access this user list"
      );
    }

    /*
     * Build the query with existing joins and selected fields.
     */
    const buildUsersQuery = (useHierarchy) => {
      let query;

      if (useHierarchy) {
        query = buildConnectedUserChain(
          loggedInUserId
        )
          .from({ u: "users" })
          .join(
            { uc: "user_chain" },
            "uc.id",
            "u.id"
          );
      } else {
        query = db.from({ u: "users" });
      }

      return query
        .leftJoin(
          { parent: "users" },
          "parent.id",
          "u.parent_id"
        )
        .leftJoin(
          { creator: "users" },
          "creator.id",
          "u.created_by"
        )
        .leftJoin(
          { rp: "role_permission" },
          "rp.id",
          "u.role_permission_id"
        )
        .leftJoin(
          { p: "profile" },
          "p.id",
          "rp.profile_id"
        );
    };

    /*
     * MASTER ADMIN:
     * Global data.
     *
     * EVERY OTHER ROLE:
     * Hierarchy-scoped data.
     */
    const useHierarchy = !canSeeAllUsers;

    // Count query: same scope and filters as the list query.
    let countQuery;

    if (useHierarchy) {
      countQuery = buildConnectedUserChain(
        loggedInUserId
      )
        .from({ u: "users" })
        .join(
          { uc: "user_chain" },
          "uc.id",
          "u.id"
        )
        .whereNot("u.id", loggedInUserId)
        .countDistinct({ total: "u.id" });
    } else {
      countQuery = db
        .from({ u: "users" })
        .countDistinct({ total: "u.id" });
    }

    applyFilters(countQuery, filters);

    const countResult = await countQuery.first();
    const total = Number(countResult?.total || 0);

    // User list query
    let usersQuery = buildUsersQuery(useHierarchy)
      .select(selectUserFields)
      .orderBy("u.id", "desc");

    // Do not include the currently logged-in user in their downline.
    if (useHierarchy) {
      usersQuery.whereNot("u.id", loggedInUserId);
    }

    applyFilters(usersQuery, filters);

    const users = await usersQuery
      .limit(limit)
      .offset(offset);

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
    const rows = await db("users")
      .select(
        "id",
        "organization_name",
        "role_id",
        "name",
        "email",
        "phone",
        "company_address",
        "country",
        "state",
        "city",
        "created_by",
        "created_at",
        "parent_id",
        "new_device",
        "old_device",
        "supreme_device",
        "pro_star",
        "lite",
        "google_tv",
        "supreme_lock"
      )
      .orderBy("id", "asc");

    return rows;
  } catch (error) {
    console.error(
      "Error fetching hierarchy users:",
      error
    );

    throw error;
  }
};

