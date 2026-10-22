
import multer from "multer";
import fs from "fs";
import path from "path";

// Upload directories
const modulesUploadDir = path.join(
  process.cwd(),
  "uploads",
  "modules"
);

const devicesUploadDir = path.join(
  process.cwd(),
  "uploads",
  "devices"
);

// Create directories if they don't exist
[modulesUploadDir, devicesUploadDir].forEach((uploadDir) => {
  if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, {
      recursive: true,
    });
  }
});

// Generate unique filename
const generateFilename = (file) => {
  const extension = path.extname(file.originalname).toLowerCase();

  return `${Date.now()}-${Math.round(
    Math.random() * 1e9
  )}${extension}`;
};

// Module icon storage
const moduleStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, modulesUploadDir);
  },

  filename: (req, file, cb) => {
    cb(null, generateFilename(file));
  },
});

// Device image storage
const deviceStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, devicesUploadDir);
  },

  filename: (req, file, cb) => {
    cb(null, generateFilename(file));
  },
});

// Allow PNG, JPG, JPEG and WEBP images
const fileFilter = (req, file, cb) => {
  const allowedMimeTypes = [
    "image/png",
    "image/jpeg",
    "image/webp",
  ];

  if (allowedMimeTypes.includes(file.mimetype)) {
    return cb(null, true);
  }

  return cb(
    new Error(
      "Only PNG, JPG, JPEG and WEBP images are allowed"
    ),
    false
  );
};

// Existing middleware: single module icon
export const uploadModuleIcon = multer({
  storage: moduleStorage,
  fileFilter,
  limits: {
    fileSize: 2 * 1024 * 1024,
  },
}).single("icon");

// Existing middleware: single new module icon
export const uploadModuleNewIcon = multer({
  storage: moduleStorage,
  fileFilter,
  limits: {
    fileSize: 2 * 1024 * 1024,
  },
}).single("newIcon");

// Device middleware: brand + customer image
export const uploadDeviceImages = multer({
  storage: deviceStorage,
  fileFilter,
  limits: {
    fileSize: 2 * 1024 * 1024,
    files: 2,
  },
}).fields([
  { name: "brand", maxCount: 1 },
  { name: "customer_image", maxCount: 1 },
]);
