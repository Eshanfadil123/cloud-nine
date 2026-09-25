require("dotenv").config()
const express = require("express")
const session = require("express-session")
const bcrypt = require("bcrypt")
const cors = require("cors")
const mongoose = require("mongoose")
const User = require("./models/User")

const app = express()
const port = 4000

// Connect to MongoDB Atlas
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("Connected to MongoDB"))
  .catch(err => console.error("MongoDB connection error:", err))

app.use(cors({
  origin: "https://cloud-nine-frontend-psi.vercel.app", // 👈 your real URL
  credentials: true
}))

app.use(express.json())
app.use(express.urlencoded({ extended: true }))

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60,
    httpOnly: true,
    secure: true,
    sameSite: "none"
  }
}))

app.post("/signup", async (req, res) => {
  const { username, password } = req.body

  const existingUser = await User.findOne({ username })
  if (existingUser) {
    return res.status(400).send("username already exists")
  }

  const hashedPassword = await bcrypt.hash(password, 10)
  const newUser = new User({ username, password: hashedPassword })
  await newUser.save()

  res.send("Account created. You can now log in.")
})

app.post("/login", async (req, res) => {
  const { username, password } = req.body

  const user = await User.findOne({ username })
  if (!user) {
    return res.status(401).send("user not found! oops")
  }

  const passWordMatches = await bcrypt.compare(password, user.password)
  if (!passWordMatches) {
    return res.status(401).send("invalid username or password")
  }

  req.session.userId = username
  res.send("logged successfully")
})

app.post("/logout", (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).send("could not log out")
    }
    res.clearCookie("connect.sid")
    res.send("logged out successFully")
  })
})

app.get("/me", (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ loggedIn: false })
  }
  res.json({ loggedIn: true, username: req.session.userId })
})

function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).send("Please log in first")
  }
  next()
}

app.get("/book-room", requireLogin, (req, res) => {
  res.send(`Welcome ${req.session.userId}, here's the booking page`)
})

app.listen(port, () => {
  console.log(`Server running on port ${port}`)
})