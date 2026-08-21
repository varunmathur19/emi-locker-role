import multer from "multer";
import fs from "fs";
import path from "path";

const uploadDir = path.join(
  process.cwd(),
  "uploads",
  "modules"
);

// ==========================================
// CREATE DIRECTORY
// ==========================================

if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, {
    recursive: true,
  });
}

// ==========================================
// STORAGE
// ==========================================

const storage = multer.diskStorage({

  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },

  filename: (req, file, cb) => {

    const extension =
      path
        .extname(file.originalname)
        .toLowerCase();

    const fileName =
      `${Date.now()}-${Math.round(
        Math.random() * 1e9
      )}${extension}`;

    cb(null, fileName);
  },

});

// ==========================================
// PNG FILTER
// ==========================================

const fileFilter = (req, file, cb) => {

  if (file.mimetype === "image/png") {

    cb(null, true);

  } else {

    cb(
      new Error(
        "Only PNG images are allowed"
      ),
      false
    );

  }

};

// ==========================================
// ADD MODULE
// FIELD = icon
// ==========================================

export const uploadModuleIcon = multer({

  storage,
  fileFilter,

  limits: {
    fileSize: 2 * 1024 * 1024,
  },

}).single("icon");


// ==========================================
// UPDATE MODULE
// FIELD = newIcon
// ==========================================

export const uploadModuleNewIcon = multer({

  storage,
  fileFilter,

  limits: {
    fileSize: 2 * 1024 * 1024,
  },

}).single("newIcon");