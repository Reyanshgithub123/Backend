import mongoose from "mongoose";
import { DB_NAME } from "../constants.js";


const connectDB = async () => {
    try {
        // Handle potential trailing slash in the URI
        const uri = process.env.MONGODB_URI.endsWith("/")
            ? process.env.MONGODB_URI.slice(0, -1)
            : process.env.MONGODB_URI;

        const connectionInstance = await mongoose.connect(`${uri}/${DB_NAME}`, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
        });

        console.log(`MongoDB connected successfully to ${DB_NAME} at ${connectionInstance.connection.host}`);
    } catch (error) {
        console.error("MongoDB connection error:", error.message);
        process.exit(1); // Exit with failure
    }
};

export default connectDB;
 