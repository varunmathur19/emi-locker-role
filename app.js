import express from "express"
import { config } from "dotenv"
config()
import {connectDB} from "./config/db.js"
import router from "./routes/auth.routes.js"
connectDB()

const app=express()

const PORT = process.env.PORT
app.use(express.json());

app.use(
"/api",
router);

app.get("/",(req,res)=>{
    res.send("hello world")
})

app.listen(PORT,(req,res)=>{
    console.log(`server is running on port ${PORT}`);
    
})