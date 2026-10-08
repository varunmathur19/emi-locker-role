import jwt from "jsonwebtoken";
import db from "../config/db.js";

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
    if (req.path === "/get-company-setting") {
      return next();
    }

    const authHeader = req.headers.authorization;

    if (
      !authHeader ||
      !authHeader.startsWith("Bearer ")
    ) {
      return next();
    }

    const token = authHeader.split(" ")[1];

    let decoded;

    try {
      decoded = jwt.verify(
        token,
        process.env.JWT_SECRET
      );
    } catch (error) {
      return next();
    }

    const roleId = Number(decoded?.role_id);

    if (roleId === 0) {
      return next();
    }

    const maintenanceSetting = await db("companysetting")
      .where("key", "maintenance")
      .where("role_id", 0)
      .select("value")
      .first();

    const maintenanceStatus = Number(
      maintenanceSetting?.value || 0
    );
    // Maintenance OFF
    if (maintenanceStatus === 0) {
      return next();
    }

    if (maintenanceStatus === 1) {
      return res.status(503).json({
        success: false,
        maintenance: true,
        message: "Application is under maintenance",
      });
    }

    return next();
  } catch (error) {
    console.error(
      "Maintenance Middleware Error:",
      error
    );

    return res.status(500).json({
      success: false,
      message: "Maintenance check failed",
    });
  }
};

export const checkSuspend = async (req, res, next) => {
  try {
    // -----------------------------------
    // Login API ko allow karo
    // Login ke time JWT nahi hota
    // -----------------------------------
    if (
      req.method === "POST" &&
      (
        req.originalUrl.includes("/login") ||
        req.originalUrl.includes("/auth/login")
      )
    ) {
      return next();
    }

    let roleId = null;

    // -----------------------------------
    // JWT se role_id nikalo
    // -----------------------------------
    const authHeader = req.headers.authorization;

    if (authHeader?.startsWith("Bearer ")) {
      const token = authHeader.substring(7).trim();

      if (token) {
        try {
          const decoded = jwt.verify(
            token,
            process.env.JWT_SECRET
          );

          roleId =
            decoded.role_id !== undefined &&
            decoded.role_id !== null
              ? Number(decoded.role_id)
              : null;
        } catch (error) {
          // Auth middleware token validate karega
        }
      }
    }

    // -----------------------------------
    // Master Admin ko suspend apply nahi hoga
    // -----------------------------------
    if (roleId === 0) {
      return next();
    }

    // -----------------------------------
    // Company setting GET allow
    // Frontend suspend status check karne ke liye
    // -----------------------------------
    if (
      req.method === "GET" &&
      req.originalUrl.includes("company-setting")
    ) {
      return next();
    }

    // -----------------------------------
    // Company setting update allow
    // Master Admin suspend OFF kar sake
    // -----------------------------------
    if (
      req.method === "PUT" &&
      req.originalUrl.includes("edit-company-setting")
    ) {
      return next();
    }

    // -----------------------------------
    // Suspend setting check
    // -----------------------------------
    const setting = await db("companysetting")
      .where("key", "suspend")
      .where("role_id", 0)
      .first();

    const isSuspended =
      String(setting?.value) === "1";

    // -----------------------------------
    // Suspended
    // -----------------------------------
    if (isSuspended) {
      return res.status(404).json({
        success: false,
        message: "Not Found",
        code: "ACCOUNT_SUSPENDED",
      });
    }

    // -----------------------------------
    // Normal request
    // -----------------------------------
    return next();
  } catch (error) {
    console.error("Suspend check error:", error);

    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};