import mongoose,{Schema} from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt"
const userSchema=new Schema({
    username:{
        type:String,
        required:true,
        unique:true,
        lowercase:true,
        trim:true,
        index:true
    },
    email:{
        type:String,
        required:true,
        unique:true,
        lowercase:true,
        trim:true,
        
    },
    fullName:{
        type:String,
        required:true,
       
       
        trim:true,
        index:true
    },
    avatar: {
        type:String,
        
        
    },
    coverImage:{
        typ:String
    },
    watchHistory:[
        {
        type:Schema.Types.ObjectId,
        ref:"Video"
}],

password:{
    type:String,
    required:[true,'Password is required'],

},
refreshToken:{
    type:String
}
},
{
    timestamps:true
})

userSchema.pre("save",async function (next) {
    if(!this.isModified("password")) return next();

    this.password=await bcrypt.hash(this.password,10)
    next()
    
})

userSchema.methods.isPasswordCorrect=async function(password){
    return await bcrypt.compare(password,this.password)
}

userSchema.methods.generateAccessToken = function () {
    if (!process.env.ACCESS_TOKEN_SECERT) {
        throw new Error("ACCESS_TOKEN_SECERT is not defined");
    }
    return jwt.sign(
        {
            _id: this._id,
            email: this.email,
            fullName: this.fullName,
            username: this.username,
        },
        process.env.ACCESS_TOKEN_SECERT,
        {
            expiresIn: process.env.ACCESS_TOKEN_EXPIRY || "15m",
        }
    );
};

userSchema.methods.generateRefereshToken = function () {
    if (!process.env.REFRESH_TOKEN_SECERT) {
        throw new Error("REFRESH_TOKEN_SECERT is not defined");
    }
    return jwt.sign(
        {
            _id: this._id,
        },
        process.env.REFRESH_TOKEN_SECERT,
        {
            expiresIn: process.env.REFRESH_TOKEN_EXPIRY || "7d",
        }
    );
};




export const User=mongoose.model("User",userSchema) 