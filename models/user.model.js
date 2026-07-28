import db from "../config/db.js";


export const findUserByEmail=async(email)=>{


const [rows]=await db.query(

"SELECT * FROM users WHERE email=?",

[email]

);


return rows[0];

}




export const createUser=async(data)=>{


const {

organization_name,
name,
email,
phone,
password,
gst,
company_address,
location,
role,
created_by

}=data;



const [result]=await db.query(

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
role,
created_by
)

VALUES(?,?,?,?,?,?,?,?,?,?)

`
,

[
organization_name,
name,
email,
phone,
password,
gst,
company_address,
location,
role,
created_by
]


);


return result.insertId;


}




export const getUserById=async(id)=>{


const [rows]=await db.query(

"SELECT id,name,email,phone,role,organization_name FROM users WHERE id=?",

[id]

);


return rows[0];


}