// import knex from "knex";
// import dotenv from "dotenv";

// dotenv.config();

// const pool = knex({
//   client: "mysql2",
//   connection: {
//     host: process.env.DB_HOST,
//     user: process.env.DB_USER,
//     password: process.env.DB_PASSWORD,
//     database: process.env.DB_NAME,
//   },
//   pool: {
//     min: 0,
//     max: 10,
//   },
// });

// export const connectDB = async () => {
//   try {
//     await pool.raw("SELECT 1");

//     console.log("✅ Database Connected Successfully");
//   } catch (error) {
//     console.error("❌ Database Connection Failed");
//     console.error(error.message);
//     process.exit(1);
//   }
// };

// export default pool;

import knex from "knex";
import dotenv from "dotenv";

dotenv.config();

const pool = knex({
  client: "mysql2",
  connection: {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
  },
  pool: {
    min: 0,
    max: 10,
  },
});

export const connectDB = async () => {
  try {
    await pool.raw("SELECT 1");
    console.log("✅ Database Connected Successfully");
  } catch (error) {
    console.error("❌ Database Connection Failed");
    console.error(error.message);
    process.exit(1);
  }
};

export default pool;