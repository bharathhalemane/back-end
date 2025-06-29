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

app.get("/", (req, res) => {
    if (req.user) {
        return res.render("dashboard")
    }
    res.render("homepage")
})

app.get("/login", (req, res) => {
    res.render("login")
})

app.get("/logout", (req, res) => {
    res.clearCookie("ourSimpleApp")
    res.redirect("/")
})

app.post("/login", (req, res) => {
    const errors = []
    if (typeof req.body.username !== "string") req.body.username = ""
    if (typeof req.body.password !== "string") req.body.password = ""

    if (req.body.username.trim() == "") errors=["Invalid username / password"]
    if (req.body.password == "") errors=["Invalid username / password"]
    
    if (errors.length) {
        return res.render("login",{errors})
    }
    const userInQuestionStatement = db.prepare("SELECT * FROM users WHERE username = ?")
    const userInQuestion = userInQuestionStatement.get(req.body.username)
    if (!userInQuestion) {
        errors = ["Invalid username / password"]   
        return res.render("login", {errors})
    }
    const matchOrNot = bcrypt.compareSync(req.body.password, userInQuestion.password)
    if(!matchOrNot) {
        errors.push("Invalid username / password")
        return res.render("login", {errors})
    }
    //log the user in give by cookie
    const ourTokenValue = jwt.sign(
        { exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24, skyColor: "blue", userInQuestion: userInQuestion.id, userInQuestion: userInQuestion.username },
        process.env.JWTSECRET
    )

    res.cookie("ourSimpleApp", ourTokenValue, {
        httpOnly: true,
        secure: true, // Use secure cookies in production
        sameSite: "strict",
        maxAge: 1000 * 60 * 60 * 24 // 1 day
    })
    res.redirect("/")
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
    
    const usernameStatement = db.prepare("SELECT * FROM users WHERE username = ?")
    const usernameCheck = usernameStatement.get("req.body.username")

    if(usernameCheck) errors.push("that username already exists")

    if (!req.body.password) errors.push("Password is required")
    if (req.body.password && req.body.password.lenght < 12) errors.push("Password must be at least 12 characters long")
    if (req.body.password && req.body.password.length > 70) errors.push("Password must be less than 70 characters long")

    
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
    
    res.redirect("/")
})

app.listen(3000)