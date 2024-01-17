const jwt = require("jsonwebtoken")

const auth = (req,res,next) =>{

    try{
     const token = req.header("AuthToken")
    
     jwt.verify(token,process.env.SECRET_KEY)

     next()

    }catch(err){
      res.status(401).send({"message": err.message})
    }

}
module.exports = auth;

