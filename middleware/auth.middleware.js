import jwt from "jsonwebtoken";

export const authMiddleware = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Token required",
      });
    }

    const token = authHeader.substring(7).trim();

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
      id:
        decoded.id !== undefined &&
        decoded.id !== null
          ? Number(decoded.id)
          : null,

      role_id:
        decoded.role_id !== undefined &&
        decoded.role_id !== null
          ? Number(decoded.role_id)
          : null,

      email: decoded.email || null,

      original_user_id:
        decoded.original_user_id !== undefined &&
        decoded.original_user_id !== null
          ? Number(decoded.original_user_id)
          : null,

      original_role_id:
        decoded.original_role_id !== undefined &&
        decoded.original_role_id !== null
          ? Number(decoded.original_role_id)
          : null,

      is_impersonating:
        decoded.is_impersonating === true ||
        decoded.is_impersonating === 1 ||
        decoded.is_impersonating === "true",
    };

    if (!req.user.id || req.user.role_id === null) {
      return res.status(401).json({
        success: false,
        message: "Invalid token payload",
      });
    }

    next();
  } catch (error) {
    console.error("Auth Middleware Error:", error.message);

    if (error.name === "TokenExpiredError") {
      return res.status(401).json({
        success: false,
        message: "Token expired",
      });
    }

    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({
        success: false,
        message: "Invalid token",
      });
    }

    return res.status(401).json({
      success: false,
      message: "Authentication failed",
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