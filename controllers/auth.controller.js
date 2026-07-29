import bcrypt from "bcrypt";

import {
    findUserByEmail,
    createUser as createUserModel,
    getAllUsers,
    findUserById, 
    getAllHierarchyUsers
} from "../models/user.model.js";
import db from "../config/db.js";
import { isValidRole } from "../constants/roles.js";
import jwt from "jsonwebtoken";


// =========================
// GET ALL Admin Master
// =========================
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
u.role_id,
u.created_at,
creator.name AS created_by_name,
creator.role_id AS created_by_role_id
FROM users u
LEFT JOIN users creator
ON u.created_by = creator.id
WHERE u.role_id = 0
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
};


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

    // Logged-in User ID from Token
    const created_by = req.user.id;

    // Check Creator Exists
    const creator = await findUserById(created_by);

    if (!creator) {
      return res.status(404).json({
        success: false,
        message: "Creator not found"
      });
    }

    // Role Validation
    if (!isValidRole(role_id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid role_id. Allowed roles are 1 to 7 only"
      });
    }

    // Hierarchy Validation
    if (Number(role_id) <= Number(creator.role_id)) {
      return res.status(400).json({
        success: false,
        message: "You cannot create same or upper level role"
      });
    }

    // Retailer Validation
 // Retailer Validation
if (Number(role_id) === 6) {

  if (
    new_device === undefined ||
    old_device === undefined ||
    supreme_device === undefined ||
    pro_star === undefined ||
    lite === undefined ||
    google_tv === undefined ||
    supreme_lock === undefined
  ) {

    return res.status(400).json({
      success: false,
      message: "All retailer device fields are required"
    });

  }


  // Only 0 and 1 allowed
  const deviceFields = [
    new_device,
    old_device,
    supreme_device,
    pro_star,
    lite,
    google_tv,
    supreme_lock
  ];


  if(deviceFields.some(value => ![0,1].includes(Number(value)))){

    return res.status(400).json({
      success:false,
      message:"Device fields only accept 0 or 1"
    });

  }

}


    // Email Check
    const existing = await findUserByEmail(email);

    if (existing) {
      return res.status(400).json({
        success: false,
        message: "Email already exists"
      });
    }

    // Password Validation
    if (password !== confirm_password) {
      return res.status(400).json({
        success: false,
        message: "Password and Confirm Password not match"
      });
    }

    // Hash Password
    const hashPassword = await bcrypt.hash(password, 10);

    // Create User
    const userId = await createUserModel({
      organization_name,
      role_id,
      name,
      email,
      phone,
      password: hashPassword,
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

    return res.status(201).json({
      success: true,
      message: "User Registered Successfully",
      data: {
        id: userId,
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
        new_device,
        old_device,
        supreme_device,
        pro_star,
        lite,
        google_tv,
        supreme_lock
      }
    });

  } catch (error) {
    console.log(error);

    return res.status(500).json({
      success: false,
      message: error.message
    });
  }
};



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