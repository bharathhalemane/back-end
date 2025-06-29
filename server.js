require("dotenv").config() // Load environment variables from .env file
const express = require("express")
const cookieParser = require("cookie-parser")
const bcrypt = require("bcrypt")
const jwt= require("jsonwebtoken")
const db = require("better-sqlite3")("ourApp.db")
db.pragma("journal_mode = WAL") // Use Write-Ahead Logging for better performance

//database setup here
const createTables = db.transaction(() => {
    db.prepare(`
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username STRING NOT NULL UNIQUE,
            password STRING NOT NULL
        )
        `).run()
})

createTables()
const app = express()

app.set("view engine", "ejs")
app.use(express.urlencoded({ extended: false }))
app.use(express.static("public"))
app.use(cookieParser()) // Middleware to parse cookies

app.use(function (req, res, next) {
    res.locals.errors = []    

    //try decode incoming cookie
    try { 
        const decoded = jwt.verify(req.cookies.ourSimpleApp, process.env.JWTSECRET)
        req.user = decoded
    } catch (err) {
        req.user = false
    }
    res.locals.user = req.user 
    console.log(req.user)
    next()
})

app.get("/homepage", (req, res) => {
    res.render("homepage")
})

app.get("/login", (req, res) => {
    res.render("login")
})

app.post("/register", (req, res) => {    // Handle registration logic here
    const errors = []
    if (typeof req.body.username !== "string") req.body.username = ""
    if (typeof req.body.password !== "string") req.body.password = ""

    req.body.username = req.body.username.trim()

    if (!req.body.username) errors.push("Username is required")
    if (req.body.username && req.body.username.length < 3) errors.push("Username must be at least 3 characters long")
    if (req.body.username && req.body.username.length > 10) errors.push("Username must be less than 10 characters long")
    if (req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/)) errors.push("Username can only contain letters and numbers")
    
    if (errors.length) {
        return res.render("homepage",{errors})
    }   
    
    // Clear the errors array for the next request
    //save the new user into a database 
    const salt = bcrypt.genSaltSync(10)
    req.body.password = bcrypt.hashSync(req.body.password, salt)
    // Insert the new user into the database
    const ourStatement = db.prepare("INSERT INTO users (username, password) VALUES (?, ?)")
    const result = ourStatement.run(req.body.username, req.body.password)
    
    const lookupStatement = db.prepare("SELECT * FROM users WHERE ROWid = ?") 
    const ourUser = lookupStatement.get(result.lastInsertRowid)
    //log the user in give by cookie
    const ourTokenValue = jwt.sign(
        { exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24, skyColor: "blue", userid: ourUser.id, username: ourUser.username },
        process.env.JWTSECRET
    )

    res.cookie("ourSimpleApp", ourTokenValue, {
        httpOnly: true,
        secure : true,
        sameSite: "strict",
        maxAge: 1000 * 60 * 60 * 24
    })
    
    res.send("Registration successful!")
})

app.listen(3000)