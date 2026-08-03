import bcrypt from "bcrypt";

import {
    findUserByEmail,
    createUser as createUserModel,
    getAllUsers,
    findUserById, 
    getAllHierarchyUsers,
} from "../models/user.model.js";
import db from "../config/db.js";
import { isValidRole } from "../constants/roles.js";
import jwt from "jsonwebtoken";
import { ROLES } from "../constants/roles.js";


// =========================
// create the user(onbaord)
// =========================
export const createuserrole = async (req, res) => {
try {
const {
organization_name,
role_id,
name,
email,
phone,
password,
confirm_password,
company_address,
country,
state,
city,
new_device,
old_device,
supreme_device,
pro_star,
lite,
google_tv,
supreme_lock
} = req.body;
// Login user id from JWT
const created_by = req.user.id;
// Creator check
const creator = await findUserById(created_by);
if(!creator){
return res.status(404).json({
success:false,
message:"Creator not found"
});
}
// Role validation

if(!isValidRole(role_id)){
return res.status(400).json({
success:false,
message:"Invalid role_id"
});
}
/*
====================================
 STAFF CREATE RULE
====================================
*/

if (Number(role_id) === ROLES.STAFF) {

    if (Number(creator.role_id) !== ROLES.ADMIN) {

        return res.status(403).json({
            success: false,
            message: "Only Admin can create Staff"
        });

    }

}
/*
====================================
 STAFF CREATE RULE
====================================
*/
// Sirf Admin Staff create karega
if(Number(role_id) === ROLES.STAFF){

if(Number(creator.role_id)!==ROLES.ADMIN){
return res.status(403).json({
success:false,
message:"Only Admin can create Staff"
});
}}
// Staff permission required

/*
====================================
 NORMAL ROLE HIERARCHY CHECK
====================================
*/
// Staff ke liye hierarchy skip hogi
if(Number(creator.role_id)!==ROLES.STAFF){
if(Number(role_id)!==ROLES.STAFF &&
Number(role_id)<=Number(creator.role_id)
){
return res.status(400).json({
success:false,
message:"You cannot create same or upper level role"
});
}
}
/*
====================================
 RETAILER DEVICE VALIDATION
====================================
*/
if(Number(role_id)===ROLES.RETAILER){
const deviceFields=[
new_device,
old_device,
supreme_device,
pro_star,
lite,
google_tv,
supreme_lock
];
if(deviceFields.some(value=>value===undefined)){
return res.status(400).json({
success:false,
message:"All retailer device fields are required"
});
}
if(
deviceFields.some(
value=>![0,1].includes(Number(value))
)
){
return res.status(400).json({
success:false,
message:"Device fields only accept 0 or 1"
});
}
}
// Email check
const existing = await findUserByEmail(email);
if(existing){
return res.status(400).json({
success:false,
message:"Email already exists"
});
}
// Password match
if(password!==confirm_password){
return res.status(400).json({
success:false,
message:"Password and Confirm Password not match"
});
}
// Password hash
const hashPassword = await bcrypt.hash(password,10);
// Create user
const userId = await createUserModel({
organization_name,
role_id,
name,
email,
phone,
password:hashPassword,
company_address,
country,
state,
city,
created_by,
new_device,
old_device,
supreme_device,
pro_star,
lite,
google_tv,
supreme_lock
});
/*
====================================
 SAVE STAFF PERMISSIONS
====================================
*/

return res.status(201).json({
success:true,
message:"User Registered Successfully",
data:{
id:userId,
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

}


});
}

catch(error){


console.log(error);


return res.status(500).json({

success:false,

message:error.message

});


}


};
// =========================
// Login staff
// =========================
export const loginUser = async (req, res) => {
  try {

    const { email, password } = req.body;

    const user = await findUserByEmail(email);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found"
      });
    }

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(401).json({
        success: false,
        message: "Invalid password"
      });
    }

    const token = jwt.sign(
      {
        id: user.id,
        role_id: user.role_id,
        email: user.email
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "7d"
      }
    );

    return res.status(200).json({
      success: true,
      message: "Login Successful",
      token
    });

  } catch (error) {

    res.status(500).json({
      success: false,
      message: error.message
    });

  }
};

// =========================
// GET ALL USERS
// =========================
export const getUsers = async(req,res)=>{

try{


const users = await getAllUsers();


res.status(200).json({

success:true,

total:users.length,

data:users

});


}
catch(error){

res.status(500).json({

success:false,
message:error.message

});

}

};

// =========================  
// GET ALL getHierarchy
// =========================
export const getHierarchyById = async (req, res) => {

    try {

        const { id } = req.params;

        const users = await getAllHierarchyUsers();

        const rootUser = users.find(x => x.id == id);

        if (!rootUser) {

            return res.status(404).json({
                success: false,
                message: "User not found"
            });

        }


        const buildTree = (userId) => {

            const children = users.filter(x => x.created_by == userId);


            return children.map(child => ({

                id: child.id,
                name: child.name,
                role_id: child.role_id,
                email: child.email,
                phone: child.phone,
                organization_name: child.organization_name,

                // Retailer Device Fields
                new_device: Number(child.new_device),
                old_device: Number(child.old_device),
                supreme_device: Number(child.supreme_device),
                pro_star: Number(child.pro_star),
                lite: Number(child.lite),
                google_tv: Number(child.google_tv),
                supreme_lock: Number(child.supreme_lock),


                children: buildTree(child.id)

            }));

        };


        const root = {

            id: rootUser.id,
            name: rootUser.name,
            role_id: rootUser.role_id,
            email: rootUser.email,
            phone: rootUser.phone,
            organization_name: rootUser.organization_name,
            // Retailer Device Fields
            new_device: Number(rootUser.new_device),
            old_device: Number(rootUser.old_device),
            supreme_device: Number(rootUser.supreme_device),
            pro_star: Number(rootUser.pro_star),
            lite: Number(rootUser.lite),
            google_tv: Number(rootUser.google_tv),
            supreme_lock: Number(rootUser.supreme_lock),


            children: buildTree(rootUser.id)

        };


        return res.status(200).json({

            success: true,

            data: root

        });


    }

    catch(error){

        res.status(500).json({

            success:false,
            message:error.message

        });

    }

};

// =========================
// Logout api
// =========================
export const logoutUser = async(req,res)=>{

try{

    const user = req.user;


    return res.status(200).json({

        success:true,
        message:"Logout Successfully",

        user:{
            // id:user.id,
            // role_id:user.role_id,
            email:user.email
        }

    });


}
catch(error){

    return res.status(500).json({

        success:false,
        message:error.message

    });

}

};        

// =========================
// User Chain Api
// =========================
export const getDropdownUsers = async (req, res) => {
  try {

    const { role_id, parent_id } = req.query;

    if (!role_id) {
      return res.status(400).json({
        success: false,
        message: "role_id is required"
      });
    }

    let sql = "";
    let values = [];

    // Admin
    if (Number(role_id) === 1) {

      sql = `
        SELECT id,name
        FROM users
        WHERE role_id=1
        ORDER BY name
      `;

    } else {
    
      if (!parent_id) {
        return res.status(400).json({
          success: false,
          message: "parent_id is required"
        });
      }

      sql = `
        SELECT id,name
        FROM users
        WHERE role_id=?
        AND created_by=?
        ORDER BY name
      `;

      values = [role_id, parent_id];
    }

    const [rows] = await db.query(sql, values);

    return res.status(200).json({
      success: true,
      total: rows.length,
      data: rows
    });

  } catch (error) {

    return res.status(500).json({
      success: false,
      message: error.message
    });

  }
}; 