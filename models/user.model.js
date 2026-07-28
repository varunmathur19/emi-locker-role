import db from "../config/db.js";


export const findUserByEmail = async(email)=>{

const [rows] = await db.query(
"SELECT * FROM users WHERE email=?",
[email]
);

return rows[0];

};

export const createUser = async(data)=>{


const {
    organization_name,
    name,
    email,
    phone,
    password,
    gst,
    company_address,
    location,
    role_id,
    created_by

}=data;



const [result] = await db.query(

`
INSERT INTO users
(
organization_name,
name,
email,
phone,
password,
gst,
company_address,
location,
role_id,
created_by
)

VALUES(?,?,?,?,?,?,?,?,?,?)

`,

[
organization_name,
name,
email,
phone,
password,
gst,
company_address,
location,
role_id,
created_by
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
u.gst,
u.company_address,
u.location,
u.role_id,
u.created_by,
u.created_at,

c.name AS created_by_name,
c.role_id AS created_by_role_id


FROM users u

LEFT JOIN users c

ON u.created_by=c.id


ORDER BY u.id ASC


`

);


return rows;

};

// Get Single User

export const getUserById = async(id)=>{

const [rows] = await db.query(

`
SELECT
id,
organization_name,
name,
email,
phone,
gst,
company_address,
location,
role_id,
created_by,
created_at

FROM users

WHERE id=?

`,

[id]

);


return rows[0];

};
