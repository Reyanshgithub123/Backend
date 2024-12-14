import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { User } from "../models/user.modal.js";

import jwt from "jsonwebtoken"

const generateAccessAndRefereshTokens = async (userId) => {
    try {
        console.log("Fetching user by ID:", userId);
        const user = await User.findById(userId);

        if (!user) {
            console.error("User not found for ID:", userId);
            throw new ApiError(404, "User not found");
        }

        console.log("Generating access and refresh tokens for user:", userId);
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefereshToken();

        console.log("Storing refresh token in the database");
        user.refreshToken = refreshToken;
        await user.save({ validateBeforeSave: false });

        console.log("Tokens generated successfully");
        return { accessToken, refreshToken };
    } catch (error) {
        console.error("Error in generateAccessAndRefereshTokens:", error);
        throw new ApiError(500, "Something went wrong while generating refresh and access tokens");
    }
};




const registerUser = asyncHandler(async (req, res) => {
     // get user details from frontend
    // validation - not empty
    // check if user already exists: username, email
    // check for images, check for avatar
    // upload them to cloudinary, avatar
    // create user object - create entry in db
    // remove password and refresh token field from response
    // check for user creation
    // return res
    try {
        const { fullName, email, username, password } = req.body;

        // Debug logs
        console.log("Request Body:", req.body);

        if ([fullName, email, username, password].some((field) => !field?.trim())) {
            console.error("Validation failed: Missing required fields");
            throw new ApiError(400, "All fields are required");
        }

        console.log("Checking if user already exists");
        const existedUser = await User.findOne({
            $or: [{ username: username.toLowerCase() }, { email: email.toLowerCase() }],
        });
        console.log("Existing User Query Result:", existedUser);
        if (existedUser) {
            throw new ApiError(409, "User with this email or username already exists");
        }

        console.log("Creating new user");
        const newUser = await User.create({
            fullName,
            email: email.toLowerCase(),
            username: username.toLowerCase(),
            password,
        });

        console.log("Fetching created user without sensitive fields");
        const createdUser = await User.findById(newUser._id).select("-password -refreshToken");

        if (!createdUser) {
            console.error("Error retrieving created user");
            throw new ApiError(500, "Something went wrong while retrieving the user");
        }

        console.log("User successfully registered:", createdUser);
        return res.status(201).json(
            new ApiResponse(201, createdUser, "User successfully registered")
        );
    } catch (error) {
        console.error("Error in registerUser:", error); // Log exact error details
        throw error;
    }
});


const logInUser=asyncHandler(async(req,res)=>{
     // req body -> data
    // username or email
    //find the user
    //password check
    //access and referesh token
    //send cookie
    const {email, username, password} = req.body
    console.log(email);
    const user = await User.findOne({
        $or: [{username}, {email}]
    })

    if (!user) {
        throw new ApiError(404, "User does not exist")
    }

   const isPasswordValid = await user.isPasswordCorrect(password)

   if (!isPasswordValid) {
    throw new ApiError(401, "Invalid user credentials")
    }

   const {accessToken, refreshToken} = await generateAccessAndRefereshTokens(user._id)

    const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
        new ApiResponse(
            200, 
            {
                user: loggedInUser, accessToken, refreshToken
            },
            "User logged In Successfully"
        )
    )
})

const logoutUser = asyncHandler(async(req, res) => {
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $unset: {
                refreshToken: 1 // this removes the field from document
            }
        },
        {
            new: true
        }
    )

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged Out"))
})

const refreshAccessToken = asyncHandler(async (req, res) => {
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken

    if (!incomingRefreshToken) {
        throw new ApiError(401, "unauthorized request")
    }

    try {
        const decodedToken = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECERT
        )
    
        const user = await User.findById(decodedToken?._id)
    
        if (!user) {
            throw new ApiError(401, "Invalid refresh token")
        }
    
        if (incomingRefreshToken !== user?.refreshToken) {
            throw new ApiError(401, "Refresh token is expired or used")
            
        }
    
        const options = {
            httpOnly: true,
            secure: true
        }
    
        const {accessToken, newRefreshToken} = await generateAccessAndRefereshTokens(user._id)
    
        return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", newRefreshToken, options)
        .json(
            new ApiResponse(
                200,  
                { accessToken, refreshToken: newRefreshToken },
                "Access token refreshed"
            )
        );
    } catch (error) {
        console.error(error,"joddd"); // Log error to check what went wrong
        throw new ApiError(401, error?.message || "Invalid refresh token");
    }
})
const changeCurrentPassword = asyncHandler(async(req, res) => {
    const {oldPassword, newPassword} = req.body

    

    const user = await User.findById(req.user?._id)
    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)

    if (!isPasswordCorrect) {
        throw new ApiError(400, "Invalid old password")
    }

    user.password = newPassword
    await user.save({validateBeforeSave: false})

    return res
    .status(200)
    .json(new ApiResponse(200, {}, "Password changed successfully"))
})

const getCurrentUser=asyncHandler(async(req,res)=>{
    return res.
    status(200).
    json(new ApiResponse(
        200,
        req.user,
        "User fetched successfully"
    ))
})

const updateUserDetails=asyncHandler(async(req,res)=>{

    const{fullName,email}=req.body
    if (!fullName || !email) {
        throw new ApiError(400, "All fields are required")
    }
    const user=await User.findByIdAndUpdate(req.user?._id,
        {
            $set:{
                fullName,email:email

            }
        },
        {
            new:true
        }
    ).select("-password")


    return res.
    status(200).
    json(new ApiResponse(200,user,"Updated successfully"))
})

const getUserChannelProfile=asyncHandler(async(req,res)=>{

    const {username}=req.params
 
    if(!username?.trim()){
        throw new ApiError(400,"User is missing")
    }
 
    const channel=await User.aggregate([
        {
            $match:{
                username:username?.toLowerCase()
            }

        },
        {
            $lookup:{
                from:"subscriptions",
                localField:"_id",
                foreignField:"channel",
                as:"subscribers"
            }
        },
        {
            $lookup:{
                from:"subscriptions",
                localField:"_id",
                foreignField:"subscriber",
                as:"subscribedTo"
            }
        },
        {
            $addFields:{
                subscriberCount:{
                    $size:"$subscribers"
                },
                subscribedToCount:{
                    $size:"$subscribedTo"
                },
                isSubscribed:{
                    $cond:{
                        if:{$in:[req.user?._id, "$subscribers.subscriber"]},
                        then: true,
                        else: false
                    }
                }
            }
        },
        {
            $project:{
                fullName: 1,
                username: 1,
                subscriberCount: 1,
                subscribedToCount: 1,
                isSubscribed: 1,
                email: 1
            }
        }
    ])

    if (!channel?.length) {
        throw new ApiError(404, "channel does not exists")
    }

    return res
    .status(200)
    .json(
        new ApiResponse(200, channel[0], "User channel fetched successfully"))
})

const getWatchHistory=asyncHandler(async(res,req)=>{
    const user = await User.aggregate([
        {
            $match: {
                _id: new mongoose.Types.ObjectId(req.user._id)
            }
        },
        {
            $lookup: {
                from: "videos",
                localField: "watchHistory",
                foreignField: "_id",
                as: "watchHistory",
                pipeline: [
                    {
                        $lookup: {
                            from: "users",
                            localField: "owner",
                            foreignField: "_id",
                            as: "owner",
                            pipeline: [
                                {
                                    $project: {
                                        fullName: 1,
                                        username: 1,
                                        avatar: 1
                                    }
                                }
                            ]
                        }
                    },
                    {
                        $addFields:{
                            owner:{
                                $first: "$owner"
                            }
                        }
                    }
                ]
            }
        }
    ])

    return res
    .status(200)
    .json(
        new ApiResponse(
            200,
            user[0].watchHistory,
            "Watch history fetched successfully"
        )
    )
})




export { registerUser , logInUser , logoutUser, refreshAccessToken, changeCurrentPassword,getCurrentUser,updateUserDetails,getUserChannelProfile,getWatchHistory};
