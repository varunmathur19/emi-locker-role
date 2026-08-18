import jwt from "jsonwebtoken";

export const authMiddleware = (req, res, next) => {
  try {
    // ==========================================
    // GET AUTHORIZATION HEADER
    // ==========================================

    const authHeader =
      req.headers.authorization;

    if (
      !authHeader ||
      !authHeader.startsWith("Bearer ")
    ) {
      return res.status(401).json({
        success: false,
        message: "Token required",
      });
    }

    // ==========================================
    // GET TOKEN
    // ==========================================

    const token =
      authHeader.split(" ")[1];

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Token required",
      });
    }

    // ==========================================
    // VERIFY TOKEN
    // ==========================================

    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

    // ==========================================
    // SET USER
    // ==========================================

    req.user = {
      id: decoded.id,
      role_id: decoded.role_id,
      email: decoded.email,

      // ========================================
      // IMPERSONATION DATA
      // ========================================

      original_user_id:
        decoded.original_user_id || null,

      original_role_id:
        decoded.original_role_id !== undefined
          ? decoded.original_role_id
          : null,

      is_impersonating:
        decoded.is_impersonating === true,
    };

    // ==========================================
    // NEXT
    // ==========================================

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