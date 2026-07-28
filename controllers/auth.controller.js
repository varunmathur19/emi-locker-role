import bcrypt from "bcrypt";

import {
    findUserByEmail,
    getUserById
} from "../models/user.model.js";
import db from "../config/db.js";


import {
    createToken
} from "../utils/jwt.js";




//get api MasterAdmin
export const getMasterAdmins = async(req,res)=>{

try{


const [users] = await db.query(

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
u.role,
u.created_at,

creator.name AS created_by_name,
creator.role AS created_by_role

FROM users u

LEFT JOIN users creator
ON u.created_by = creator.id

WHERE u.role='MASTER_ADMIN'

`

);



res.status(200).json({

success:true,
count:users.length,
data:users

});


}
catch(error){

console.log(error);

res.status(500).json({

success:false,
message:error.message

});

}


}


//create admin 
export const createUser = async(req,res)=>{

try{


const {
organization_name,
role,
name,
email,
phone,
password,
gst,
company_address,
location
}=req.body;



// check email

const [existing] = await db.query(
"SELECT id FROM users WHERE email=?",
[email]
);


if(existing.length > 0){

return res.status(400).json({

success:false,
message:"Email already exists"

});

}



// password hash

const hashPassword = await bcrypt.hash(password,10);



// insert user

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
role
)

VALUES(?,?,?,?,?,?,?,?,?)

`,

[
organization_name,
name,
email,
phone,
hashPassword,
gst,
company_address,
location,
role
]

);



const [user] = await db.query(

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
role,
created_at
FROM users
WHERE id=?

`,

[result.insertId]

);



res.status(201).json({

success:true,
message:`${role} Created Successfully`,
data:user[0]

});


}
catch(error){

console.log(error);

res.status(500).json({

success:false,
message:error.message

});

}


}

//get masterAdmin for role
export const getAllUsers = async(req,res)=>{

    try{


        const [users] = await db.query(
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
            role,
            created_at
            FROM users
            ORDER BY id DESC
            `
        );


        res.status(200).json({

            success:true,

            total:users.length,

            data:users

        });


    }
    catch(error){

        console.log(error);


        res.status(500).json({

            success:false,

            message:error.message

        });

    }

};
