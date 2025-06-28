const express = require("express")
const bcrypt = require("bcrypt")
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

app.use(function (req, res, next) {
    res.locals.errors = []    
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
    
    
    if(typeof req.body.username !== "string" || req.body.username.length < 3) {
        errors.push("Username must be at least 3 characters long")
    }
    if (typeof req.body.password === "string") {
        if (req.body.password.length < 5) {
            errors.push("Password must be at least 5 characters long")
        }
        if (req.body.password.length > 20) {
            errors.push("Password must be at most 20 characters long")
        }
    } 

    if (!req.body.username) errors.push("Username cannot be empty")
    if (!req.body.password) errors.push("Password cannot be empty")
    if (req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/)) errors.push("Username must contain only alphanumeric characters")
    req.body.username = req.body.username.trim()
    if (errors.length) {        
        return res.render("homepage",{errors})
    }
        
    
    errors.splice(0, errors.length) // Clear the errors array for the next request
    //save the new user into a database 
    const salt = bcrypt.genSaltSync(10)
    req.body.password = bcrypt.hashSync(req.body.password, salt)
    const ourStatement = db.prepare("INSERT INTO users (username, password) VALUES (?, ?)")
    ourStatement.run(req.body.username, req.body.password)
    
     // Clear the errors array after successful registration
    //log the user in give by cookie
    res.cookie("ourSimpleApp", "supertopsecretvalue", {
        httpOnly: true,
        secure : true,
        sameSite: "strict",
        maxAge: 1000 * 60 * 60 * 24
    })
    
    res.send("Registration successful!")
})

app.listen(3000)