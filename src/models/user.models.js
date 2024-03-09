import mongoose,{Schema} from "mongoose";
import bcrypt from "bcrypt"
import  Jwt  from "jsonwebtoken";

const UserSchema=new Schema({
    userName:{
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
    avatar:{
        type:String,
        required:true,
    },
    coverImage:{
        type:String,
    },
    watchHistory:[{
        type:Schema.Types.ObjectId,
        ref:"Video"
    }],
    password:{
        type:String,
        required:[true,"Password is required"]
    },
    refreshToken:{
        type:String,
    }

},{timeseries:true})

UserSchema.pre("save",async function(next){
   if(!this.isModified("password")) return next()

    this.password=await bcrypt.hash(this.password,10)
    next()
})

UserSchema.methods.isPasswordCorrect=async function(password){
    return await bcrypt.compare(password,this.password)
}

UserSchema.method.generateAccessToken=function(){
    return Jwt.sign(
        {
            _id:this._id,
            email:this.email,
            userName:this.userName,
            fullName:this.fullName
        },
        process.env.ACCESS_TOKEN_SECRET,{
            expiresIn:process.env.ACCESS_TOKEN_EXPIRY
        }
    )
}
UserSchema.method.generateRefreshToken=function(){
    return Jwt.sign(
        {
            _id:this._id,
            email:this.email,
            userName:this.userName,
            fullName:this.fullName
        },
        process.env.REFRESH_TOKEN_SECRET,{
            expiresIn:process.env.REFRESH_TOKEN_EXPIRY
        }
    )
}
export const User= mongoose.model("User",UserSchema)
