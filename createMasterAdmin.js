import "dotenv/config";
import bcrypt from "bcrypt";
import db from "./config/db.js";


// Create Master Admin

const createMasterAdmin = async()=>{

try{


const {
    MASTER_ADMIN_NAME,
    MASTER_ADMIN_EMAIL,
    MASTER_ADMIN_PASSWORD,
    MASTER_ADMIN_PHONE

}=process.env;



const password = await bcrypt.hash(
    MASTER_ADMIN_PASSWORD,
    10
);



await db.query(

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
role_id
)

VALUES(?,?,?,?,?,?,?,?,?)

`,

[
"Rechargkit",
MASTER_ADMIN_NAME,
MASTER_ADMIN_EMAIL,
MASTER_ADMIN_PHONE,
password,
"NA",
"Head Office",
"India",
0
]

);



console.log("Master Admin Created Successfully");


process.exit();


}
catch(error){


console.log(error);

process.exit(1);


}


};



createMasterAdmin();