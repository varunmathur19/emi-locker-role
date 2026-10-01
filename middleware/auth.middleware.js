import jwt from "jsonwebtoken";

export const authMiddleware = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (
      !authHeader ||
      !authHeader.startsWith("Bearer ")
    ) {
      return res.status(401).json({
        success: false,
        message: "Token required",
      });
    }

    const token = authHeader.split(" ")[1];

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Token required",
      });
    }

    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

    req.user = {
      id: decoded.id,

      role_id:
        decoded.role_id !== undefined
          ? Number(decoded.role_id)
          : null,

      email: decoded.email,

      original_user_id:
        decoded.original_user_id || null,

      original_role_id:
        decoded.original_role_id !== undefined &&
        decoded.original_role_id !== null
          ? Number(decoded.original_role_id)
          : null,

      is_impersonating:
        decoded.is_impersonating === true,
    };

    next();

  } catch (error) {
    console.error(
      "Auth Middleware Error:",
      error.message
    );

    return res.status(401).json({
      success: false,
      message: "Invalid Token",
    });
  }
};

export const maintenanceMiddleware = async (req, res, next) => {
  try {
    const roleId = Number(req.user?.role_id);

    if (roleId === 0) {
      return next();
    }

    const maintenance = await db("companysetting")
      .where("key", "maintenance")
      .where("role_id", 0)
      .select("value")
      .first();

    const isMaintenance =
      Number(maintenance?.value) === 1;

    if (isMaintenance) {
      return res.status(503).json({
        success: false,
        maintenance: true,
        message: "Application is under maintenance",
      });
    }

    next();
  } catch (error) {
    console.error(
      "Maintenance Middleware Error:",
      error
    );

    next();
  }
};