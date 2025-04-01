const mongoose = require("mongoose");

const connectDB = () => {
    mongoose.connect(process.env.MONGO_URI)
    .then((connection) => {
        console.log(`MongoDB connected: ${connection.connection.host}`);
    })
    .catch((error) => {
        console.error("Failed to connect to MongoDB", error);
    });
};

module.exports = { connectDB };

// connectDB();
