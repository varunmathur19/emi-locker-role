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
      // CURRENT USER
      id: decoded.id,

      role_id:
        decoded.role_id !== undefined
          ? Number(decoded.role_id)
          : null,

      email: decoded.email,

      // ORIGINAL LOGIN USER
      original_user_id:
        decoded.original_user_id || null,

      original_role_id:
        decoded.original_role_id !== undefined &&
        decoded.original_role_id !== null
          ? Number(decoded.original_role_id)
          : null,

      // IMPERSONATION
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