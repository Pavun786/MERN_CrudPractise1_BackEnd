const express = require("express")
const dotenv = require("dotenv")
const cors = require("cors")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const {MongoClient, ObjectId} = require("mongodb")
const auth = require("./middleware/auth.js")
const nodemailer = require("nodemailer");
const app = express()

dotenv.config()

app.use(express.json())
app.use(cors({
origin: "*"
}))


const Mongo_url = process.env.MONGO_URL;

let client;

async function DbConnection(){
    client = new MongoClient(Mongo_url)
    await client.connect()
    console.log("The DB connected")
}
DbConnection()


const port = 4200 || process.env.PORT ;

app.get("/",(req,res)=>{
    res.send("Hi Guys.Please welcome my app")
})

app.post("/",auth,async (req,res)=>{
    const data = req.body;
    
    const result = await client.db("data_createapp").collection("personDetails").insertOne(data)
    // const result = await client.db("data_createapp").collection("personDetails").insertMany(data)

  
        res.status(200).send({"message": "data added successfully"})
    
})

app.get("/all",async (req,res)=>{
    const result = await client.db("data_createapp").collection("personDetails").find({}).toArray()
    
        res.status(200).send(result)
   
})


app.get("/:id",async (req,res)=>{

    
        const {id} = req.params;
       
        const result = await client.db("data_createapp").collection("personDetails").findOne({_id : new ObjectId(id)})
        console.log(result)
        
        res.status(200).send(result)
    
})

app.put("/:id",auth,async (req,res)=>{
    const {id} = req.params;
    const data = req.body
    const result = await client.db("data_createapp").collection("personDetails").updateOne({ _id : new ObjectId(id)},{$set:data})
    res.status(200).send({"message": "data updated successfully"})
})

app.delete("/:id",auth,async(req,res)=>{
    const id = req.params;
    const result = await client.db("data_createapp").collection("personDetails").deleteOne({_id : new ObjectId(id)})
    res.status(200).send({"message": "data deleted successfully"})
})


app.post("/register",async(req,res)=>{

  const {username,email,password} = req.body;

    const findUser = await client.db("data_createapp").collection("auth").findOne({email : email})

    if(findUser){
        res.send("User Already Exists")
    }
    else if(password.length < 8){
        res.send("Please provide strong password")
    }
   else{
    
      const NoOfRounds = 10;
      const salt = await bcrypt.genSalt(NoOfRounds)
      const hashedPassword =await bcrypt.hash(password,salt)
   
      const createUser = await client.db("data_createapp").collection("auth").insertOne({
            username : username,
            email : email,
            password : hashedPassword 
        })
        res.status(200).send("User registered successfully..!")
    }

})

app.post("/login",async (req,res)=>{
    const {email,password} = req.body;
 
    const findUser = await client.db("data_createapp").collection("auth").findOne({email : email})
    
    console.log("findUser",findUser)
    if(findUser){

        const passwordCompare = await bcrypt.compare(password,findUser.password)

        if(passwordCompare){

           const token = jwt.sign({id: findUser._id},process.env.SECRET_KEY)

            res.status(200).send({"token" : token ,"message":"User logined successfully"})
        }else{
            res.status(401).send({"message":"UnAuthorized credentials"})
        }
    }else{
        res.status(401).send({"message":"UnAuthorized credentials"})
    }

})

app.post("/emailSend",async(req,res)=>{

    const {email} = req.body;

    const findUser = await client.db("data_createapp").collection("auth").findOne({email : email})
    console.log(findUser)
    if(!findUser){
        res.status(404).send({"message" : "User not found"})
    }else{
        const token = jwt.sign(email,process.env.SECRET_KEY)
          const transporter = nodemailer.createTransport({
            // host: "smtp.forwardemail.net",
            service: 'gmail',
            auth: {
  // TODO: replace `user` and `pass` values from <https://forwardemail.net>
              user: process.env.EMAIL,
              pass: process.env.PASSWORD,
            },
          });
    
         transporter.sendMail({
            from: process.env.EMAIL, // sender address
            to: email, // list of receivers
            subject: "Password Reset✔", // Subject line
            // text: "Please click the bellow link to reset the password?", // plain text body
            text: `http://localhost:3000/${findUser._id}/${token}`, 
          },(error, info) => {
            if (error) {
              console.error('Error:', error);
            } else {
              console.log('Email sent:', info.response);
            }
          });
    }
   
    
     res.status(200).send({"message":"The mail is sended"})
})

app.put("/:id/resetPassword",async (req,res)=>{
    
   
        const {id} = req.params;
        const {newPassword} = req.body;

        if(newPassword.length < 8){
            res.send("Provide more than length of 8 character")
        }
        else{
            const findUserById = await client.db("data_createapp").collection("auth").findOne({_id : new ObjectId(id)})
    
            if(!findUserById){
                res.status(404).send({"message" : "User not found..!"})
            }else{
                const NoOfRounds = 10;
                const salt = await bcrypt.genSalt(NoOfRounds)
                const hashedPassword =await bcrypt.hash(newPassword,salt)
                const result = await client.db("data_createapp").collection("auth").updateOne({ _id : new ObjectId(id)},{$set : {password : hashedPassword}})
                console.log(result)
                res.status(200).send({"message":"Password reset successfully..!"})   
            }
        
        }
        
})


app.listen(port ,()=>{
    console.log(`The server running on PORT ${port}`)
})