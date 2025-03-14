require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const connectDB = require("./config");
const router = require("./routes/auth");

connectDB();

const app = express();
app.use(express.json());
app.use(cors());
app.use(helmet());

// Register & login auth routes
app.use('/api/auth', router);

app.get("/", (req, res) => res.send("Cybersecurity Advisor API Running..."));

const PORT = process.env.PORT || 3000
app.listen(PORT, () => console.log("🚀 Server running..."));
