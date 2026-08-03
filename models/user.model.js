import db from "../config/db.js";
import pool from "../config/db.js";

export const findUserByEmail = async(email)=>{

const [rows] = await db.query(
"SELECT * FROM users WHERE email=?",
[email]
);

return rows[0];

};

export const findUserById = async (id) => {

  const [rows] = await db.query(

    `
    SELECT 
    id,
    name,
    role_id
    FROM users
    WHERE id=?
    `,
    [id]

  );


  return rows[0];

};

export const createUser = async (data) => {

 const {

  organization_name,
  name,
  email,
  phone,
  password,
  company_address,
  country,
  state,
  city,
  role_id,
  created_by,

  new_device = 0,
  old_device = 0,
  supreme_device = 0,
  pro_star = 0,
  lite = 0,
  google_tv = 0,
  supreme_lock = 0

 } = data;


  const [result] = await db.query(

    `
    INSERT INTO users
    (
      organization_name,
      name,
      email,
      phone,
      password,
      company_address,
      country,
      state,
      city,
      role_id,
      created_by,
      new_device,
      old_device,
      supreme_device,
      pro_star,
      lite,
      google_tv,
      supreme_lock
    )

    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    `,

    [
      organization_name,
      name,
      email,
      phone,
      password,
      company_address,
      country,
      state,
      city,
      role_id,
      created_by,

      Number(new_device),
      Number(old_device),
      Number(supreme_device),
      Number(pro_star),
      Number(lite),
      Number(google_tv),
      Number(supreme_lock)
    ]

  );

  return result.insertId;

};
// Get All Users
export const getAllUsers = async()=>{


const [rows] = await db.query(

`

SELECT

u.id,
u.organization_name,
u.name,
u.email,
u.phone,
u.company_address,
u.country,
u.state,
u.city,
u.role_id,
u.created_by,
u.created_at,

c.name AS created_by_name,
c.role_id AS created_by_role_id


FROM users u

LEFT JOIN users c

ON u.created_by = c.id


ORDER BY u.id ASC


`

);


return rows;

};

//get getAllHierarchyUsers 
export const getAllHierarchyUsers = async () => {

    const [rows] = await db.query(`
        SELECT
            id,
            organization_name,
            role_id,
            name,
            email,
            phone,
            company_address,
            country,
            state,
            city,
            created_by,
            created_at,

            new_device,
            old_device,
            supreme_device,
            pro_star,
            lite,
            google_tv,
            supreme_lock

        FROM users
        ORDER BY id ASC
    `);

    return rows;

};



