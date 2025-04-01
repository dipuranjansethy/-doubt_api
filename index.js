const express = require("express");
const { connectDB } = require("./config/database.js");
const dotenv = require("dotenv");
const cookieParser = require('cookie-parser');
const cors = require('cors');
const userRouter = require('./routes/userRoutes');
dotenv.config();
const PORT = process.env.PORT || 4000;
const teacherRoutes = require('./routes/teacherRoutes');
const reviewRoutes = require('./routes/reviewRoutes.js');

connectDB();

const app = express();

app.use(cors({
  origin: true, // Temporarily allow all origins
  credentials: true, // Allow credentials (cookies, headers)
}));

app.use(express.json());
app.use(cookieParser());

app.use('/api/v1/users', userRouter);
app.use('/api/v1/teachers', teacherRoutes);
app.use('/api/v1/reviews', reviewRoutes);


app.listen(PORT, () => {
  console.log(`App listening on port ${PORT}`);
});