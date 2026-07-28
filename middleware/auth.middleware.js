import jwt from "jsonwebtoken";
import db from "../config/db.js";


export const authMiddleware = async(req,res,next)=>{

try{

const token = req.headers.authorization?.split(" ")[1];


if(!token){

return res.status(401).json({
message:"Token Required"
});

}


const decoded = jwt.verify(
token,
process.env.JWT_SECRET
);



const [users] = await db.query(
"SELECT id,name,email,role FROM users WHERE id=?",
[decoded.id]
);



if(users.length===0){

return res.status(404).json({
message:"User not found"
});

}


req.user = users[0];


next();


}
catch(error){

console.log(error);

res.status(401).json({
message:"Invalid Token"
});

}

};



export const isMasterAdmin = (req,res,next)=>{


if(!req.user){

return res.status(401).json({
message:"Unauthorized"
});

}


if(req.user.role !== "MASTER_ADMIN"){

return res.status(403).json({
message:"Only Master Admin can create Admin"
});

}


next();

};