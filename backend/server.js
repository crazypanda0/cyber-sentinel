require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const connectDB = require("./config");
const router = require("./routes/auth");
const userRoutes = require("./routes/user");
const phishingRoutes = require("./routes/phishingRoutes");

connectDB();

const app = express();
app.use(express.json());
app.use(cors());
app.use(helmet());

// Register & login auth routes
app.use('/api/auth', router);
app.use('/api/user', userRoutes)
app.use('/api/phishing', phishingRoutes)

app.get("/", (req, res) => res.send("Cyber-Sentinel API Running..."));

const PORT = process.env.PORT || 3000
app.listen(PORT, () => console.log("🚀 Server running..."));
