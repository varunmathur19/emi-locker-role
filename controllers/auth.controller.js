import bcrypt from "bcrypt";

import {
    findUserByEmail,
    createUser as createUserModel,
   
    getAllUsers
} from "../models/user.model.js";
import db from "../config/db.js";
import { isValidRole } from "../constants/roles.js";

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



export const createuserrole = async (req, res) => {
  try {

    const {
      organization_name,
      role_id,
      name,
      email,
      phone,
      password,
      gst,
      company_address,
      location,
      created_by
    } = req.body;



    // Role Validation

    if(!isValidRole(role_id)){

      return res.status(400).json({

        success:false,
        message:"Invalid role_id. Allowed roles are 1 to 7 only"

      });

    }



    // Check Email

    const existing = await findUserByEmail(email);


    if (existing) {

      return res.status(400).json({

        success: false,
        message: "Email already exists"

      });

    }



    // Password Hash

    const hashPassword = await bcrypt.hash(password, 10);



    // Create User

    const userId = await createUserModel({

      organization_name,
      name,
      email,
      phone,
      password: hashPassword,
      gst,
      company_address,
      location,
      role_id,
      created_by: created_by || null

    });



    res.status(201).json({

      success: true,

      message: "User Registered Successfully",

      data: {

        id: userId,
        organization_name,
        role_id,
        name,
        email,
        phone,
        gst,
        company_address,
        location,
        created_by: created_by || null

      }

    });



  } catch (error) {

    console.log(error);

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









