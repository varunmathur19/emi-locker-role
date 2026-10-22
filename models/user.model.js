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

const getHierarchyAnchorUserId = async (userId, roleId = null) => {
  const currentUser = await db("users")
    .select("id", "role_id", "parent_id", "created_by")
    .where("id", Number(userId))
    .first();

  if (!currentUser) {
    return Number(userId);
  }

  const normalizedRoleId = Number(roleId ?? currentUser.role_id ?? 0);
  const creatorId =
    currentUser.created_by !== null &&
    currentUser.created_by !== undefined &&
    currentUser.created_by !== ""
      ? Number(currentUser.created_by)
      : null;

  const parentId =
    currentUser.parent_id !== null &&
    currentUser.parent_id !== undefined &&
    currentUser.parent_id !== ""
      ? Number(currentUser.parent_id)
      : null;

  // Staff follows the person who created the staff record.
  if (normalizedRoleId === 9) {
    if (creatorId) {
      return creatorId;
    }

    if (parentId) {
      return parentId;
    }

    return Number(currentUser.id);
  }

  // For all non-staff hierarchy users, the current user is the root of the branch.
  // The returned branch contains records where this user sits as the ancestor.
  if (parentId) {
    return Number(currentUser.id);
  }

  if (creatorId) {
    return Number(currentUser.id);
  }

  return Number(currentUser.id);
};

const getEffectiveHierarchyScope = async (userId, roleId) => {
  const normalizedRoleId = Number(roleId);

  if (normalizedRoleId !== 9) {
    return {
      userId: Number(userId),
      roleId: normalizedRoleId,
    };
  }

  const currentUser = await db("users")
    .select("id", "created_by", "role_id")
    .where("id", Number(userId))
    .first();

  if (!currentUser) {
    return {
      userId: Number(userId),
      roleId: normalizedRoleId,
    };
  }

  const creatorId =
    currentUser.created_by !== null &&
    currentUser.created_by !== undefined &&
    currentUser.created_by !== ""
      ? Number(currentUser.created_by)
      : null;

  if (!creatorId) {
    return {
      userId: Number(currentUser.id),
      roleId: Number(currentUser.role_id ?? normalizedRoleId),
    };
  }

  const creator = await db("users")
    .select("id", "role_id")
    .where("id", creatorId)
    .first();

  if (!creator) {
    return {
      userId: Number(currentUser.id),
      roleId: Number(currentUser.role_id ?? normalizedRoleId),
    };
  }

  return {
    userId: Number(creator.id),
    roleId: Number(creator.role_id ?? normalizedRoleId),
  };
};

const buildConnectedUserChain = (startUserId, includeCreatedBy = false) =>
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
              if (includeCreatedBy) {
                this.on("child.parent_id", "=", "current.id")
                  .orOn("child.created_by", "=", "current.id");
                return;
              }

              this.on("child.parent_id", "=", "current.id");
            });
        });
    }
  );

const getStaffCreatorUserId = async (staffUserId) => {
  const staffUser = await db("users")
    .select("id", "created_by")
    .where("id", Number(staffUserId))
    .first();

  if (!staffUser) {
    return Number(staffUserId);
  }

  if (
    staffUser.created_by !== null &&
    staffUser.created_by !== undefined &&
    staffUser.created_by !== ""
  ) {
    return Number(staffUser.created_by);
  }

  return Number(staffUser.id);
};



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
  staffRoleAccess = false,
  staffCreatorId = null,
  canSeeAllUsersParam = null,
  transferTargetRoleId = null
) => {
  try {
    // 1. Validate pagination and logged-in user
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

    // 2. Role configuration
    const MASTER_ADMIN_ROLE_ID = 0;
    const ADMIN_ROLE_ID = 1;
    const STAFF_ROLE_ID = 9;

    const isMasterAdmin =
      loggedInRoleId === MASTER_ADMIN_ROLE_ID;

    const isAdmin =
      loggedInRoleId === ADMIN_ROLE_ID;

    const isStaff =
      loggedInRoleId === STAFF_ROLE_ID;

    // 3. Determine full-user access
    let canSeeAllUsers;

    if (
      canSeeAllUsersParam === null ||
      canSeeAllUsersParam === undefined
    ) {
      canSeeAllUsers = isMasterAdmin || isAdmin;
    } else {
      if (typeof canSeeAllUsersParam !== "boolean") {
        throw new Error(
          "Invalid full-user access permission"
        );
      }

      canSeeAllUsers =
        canSeeAllUsersParam &&
        (isMasterAdmin || isAdmin || isStaff);
    }

    // IMPORTANT:
    // Do not reject Staff based on staffRoleAccess here.
    // This function is used for user lists and dashboard counts.
    // Transfer-specific permissions must be checked by the
    // actual Transfer, Revert, and Schema Transfer endpoints.
    //
    // staffRoleAccess is retained in the signature to avoid
    // breaking existing callers.

    // 4. Normalize filters
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

    const normalizedRole = normalizeFilter(role_id);

    const filters = {
      role_id:
        normalizedRole === null
          ? null
          : Number(normalizedRole),

      search: normalizeFilter(search),
      country: normalizeFilter(country),
      state: normalizeFilter(state),
      city: normalizeFilter(city),

      status:
        status === null ||
        status === undefined ||
        String(status).trim() === ""
          ? null
          : Number(status),
    };

    if (
      filters.role_id !== null &&
      (
        !Number.isInteger(filters.role_id) ||
        filters.role_id < 0
      )
    ) {
      throw new Error("Invalid role_id");
    }

    if (
      filters.status !== null &&
      ![0, 1].includes(filters.status)
    ) {
      throw new Error("Invalid status");
    }

    // 5. Resolve Staff creator
    let resolvedStaffCreatorId = null;
    let staffCreatorRoleId = null;

    if (isStaff) {
      const staffUser = await db("users")
        .select("id", "created_by", "parent_id")
        .where("id", loggedInUserId)
        .first();

      if (!staffUser) {
        throw new Error("Staff user not found");
      }

      const creatorValue =
        staffCreatorId ??
        staffUser.created_by ??
        staffUser.parent_id;

      resolvedStaffCreatorId = Number(creatorValue);

      if (
        !Number.isInteger(resolvedStaffCreatorId) ||
        resolvedStaffCreatorId <= 0 ||
        resolvedStaffCreatorId === loggedInUserId
      ) {
        throw new Error(
          "Staff creator could not be identified"
        );
      }

      const creator = await db("users")
        .select("id", "role_id")
        .where("id", resolvedStaffCreatorId)
        .first();

      if (!creator) {
        throw new Error("Staff creator not found");
      }

      staffCreatorRoleId = Number(creator.role_id);

      // Verify full-user access against the actual creator.
      if (
        canSeeAllUsers &&
        ![
          MASTER_ADMIN_ROLE_ID,
          ADMIN_ROLE_ID,
        ].includes(staffCreatorRoleId)
      ) {
        throw new Error(
          "Invalid full-user access permission"
        );
      }

      console.log("STAFF USER SCOPE:", {
        staffId: loggedInUserId,
        creatorId: resolvedStaffCreatorId,
        creatorRoleId: staffCreatorRoleId,
        transferTargetRoleId,
      });
    }

    // 6. Resolve hierarchy for restricted roles
    let hierarchyAnchorId = null;

    if (!canSeeAllUsers) {
      const scopeUserId = isStaff
        ? resolvedStaffCreatorId
        : loggedInUserId;

      const scopeRoleId = isStaff
        ? staffCreatorRoleId
        : loggedInRoleId;

      const effectiveScope =
        await getEffectiveHierarchyScope(
          scopeUserId,
          scopeRoleId
        );

      hierarchyAnchorId = await getHierarchyAnchorUserId(
        effectiveScope?.userId ?? scopeUserId,
        effectiveScope?.roleId ?? scopeRoleId
      );

      hierarchyAnchorId = Number(hierarchyAnchorId);

      if (
        !Number.isInteger(hierarchyAnchorId) ||
        hierarchyAnchorId <= 0
      ) {
        throw new Error(
          "Unable to resolve hierarchy scope"
        );
      }
    }

    // 7. Build base query
    const buildBaseQuery = () => {
      if (canSeeAllUsers) {
        return db({ u: "users" });
      }

      return buildConnectedUserChain(
        hierarchyAnchorId,
        false
      ).from({ u: "users" });
    };

    // 8. Apply hierarchy access scope
    const applyAccessScope = (query) => {
      if (canSeeAllUsers) {
        return query;
      }

      query.leftJoin(
        { uc: "user_chain" },
        "uc.id",
        "u.id"
      );

      query.where(function () {
        // Non-Staff users inside the resolved hierarchy.
        this.where(function () {
          this.where("u.role_id", "!=", STAFF_ROLE_ID)
            .whereNotNull("uc.id");
        });

        // Staff users directly linked to the applicable parent.
        this.orWhere(function () {
          this.where("u.role_id", STAFF_ROLE_ID)
            .andWhere(function () {
              this.where(
                "u.parent_id",
                isStaff
                  ? resolvedStaffCreatorId
                  : loggedInUserId
              ).orWhere(
                "u.created_by",
                isStaff
                  ? resolvedStaffCreatorId
                  : loggedInUserId
              );
            });
        });
      });

      return query;
    };

    // 9. Exclude current user for restricted access
    const applyUserExclusion = (query) => {
      if (!canSeeAllUsers) {
        query.whereNot("u.id", loggedInUserId);
      }

      return query;
    };

    // 10. Count matching users
    const countQuery = applyUserExclusion(
      applyAccessScope(buildBaseQuery())
    );

    applyFilters(countQuery, filters);

    const countResult = await countQuery
      .countDistinct({ total: "u.id" })
      .first();

    const total = Number(countResult?.total || 0);

    // 11. Fetch user records
    const usersQuery = applyUserExclusion(
      applyAccessScope(buildBaseQuery())
    );

    usersQuery
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
      )
      .select(selectUserFields)
      .distinct("u.id")
      .orderBy("u.id", "desc");

    applyFilters(usersQuery, filters);

    const users = await usersQuery
      .limit(limit)
      .offset(offset);

    // 12. Debug output
    console.log("GET ALL USERS MODEL RESULT:", {
      loggedInUserId,
      loggedInRoleId,
      canSeeAllUsers,
      isStaff,
      staffCreatorId: resolvedStaffCreatorId,
      staffCreatorRoleId,
      hierarchyAnchorId,
      roleFilter: filters.role_id,
      returnedUsers: users.length,
      totalUsers: total,
      limit,
      offset,
    });

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

