require("dotenv").config();
const express = require("express");
const app = express();
const cors = require("cors");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt"); // used to hash password
const jwt = require("jsonwebtoken"); // used to create tokens
const bodyParser = require("body-parser");

// Citation Scope: Implementation of cors for frontend to backend communication, bcrypt for password hashing
// Date: 05/04/2025
// Originality: Adapted
// Source: https://www.youtube.com/watch?v=dICDmbgGFdE&list=PLzF6FKB4VN3_8lYlLOsJI8hElGLRgUs7C
// Author: TechCheck

const PORT = process.env.PORT || 8088;

app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.json());
app.use(cors());

// database connection for users
const db = mysql.createPool({
  connectionLimit: 10,
  host: process.env.MYSQLHOST,
  user: process.env.MYSQLUSER,
  port: process.env.MYSQLPORT || 3306,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
});

// generates token
const generateToken = (user_id, username) =>
  jwt.sign({ user_id, username }, process.env.JWT_SECRET, { expiresIn: "1h" });

const saltRounds = 10;

// inserts new user to database, creates session token
app.post("/signup", async (req, res) => {
  const { username, password, first_name, last_name, email } = req.body;
  try {
    const hashed_password = await bcrypt.hash(password, saltRounds);

    await db.query(
      "INSERT INTO users (username, password, first_name, last_name, email) VALUES (?, ?, ?, ?, ?)",
      [username, hashed_password, first_name, last_name, email]
    );

    const [result] = await db.query("SELECT * FROM users WHERE username = ?", [
      username,
    ]);

    if (result.length === 0)
      return res.status(400).json({ message: "User not found" });

    const user = result[0];

    await db.query("UPDATE users SET logged_in = true WHERE user_id = ?", [
      user.user_id,
    ]);

    const token = generateToken(user.user_id, user.username);

    console.log("Sent from Microservice B", {
      token: token,
      username: user.username,
      id: user.user_id,
    });
    res.status(201).json({
      token,
      message: "User registered",
      username: user.username,
      user_id: user.user_id,
    });
  } catch (err) {
    res.status(400).json({ error: "Database error" });
  }
});

// checks database for user authentication for login
app.post("/signin", async (req, res) => {
  const { username, password } = req.body;
  try {
    const [rows] = await db.query("SELECT * FROM users WHERE username = ?", [
      username,
    ]);
    if (rows.length === 0)
      return res.status(400).json({ message: "User not found" });

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: "Invalid credentials" });

    await db.query("UPDATE users SET logged_in = true WHERE user_id = ?", [
      user.user_id,
    ]);

    const token = generateToken(user.user_id, user.username);
    console.log("Sent from Microservice B", {
      token: token,
      username: user.username,
      id: user.user_id,
    });
    res.json({
      token,
      message: "Logged in",
      username: user.username,
      user_id: user.user_id,
    });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// updates logout state
app.post("/logout", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    await db.query("UPDATE users SET logged_in = false WHERE user_id = ?", [
      decoded.user_id,
    ]);
    console.log("logged out");
    res.json({ message: "Logged out" });
  } catch (err) {
    res.status(400).json("error: 'Invalid token");
  }
});

// checks user state
app.get("/state/:username", async (req, res) => {
  const { username } = req.params;
  const [rows] = await db.query(
    "SELECT logged_in FROM users WHERE username = ?",
    [username]
  );
  if (rows.length === 0)
    return res.status(400).json({ message: "User not found" });

  res.json({ logged_in: rows[0].logged_in });
});

// fetches user information
app.get("/get-user/:user_id", async (req, res) => {
  const { user_id } = req.params;

  console.log(`Fetching data for user: ${user_id}`);

  try {
    const [results] = await db.query("SELECT * FROM users WHERE user_id = ?", [
      user_id,
    ]);

    if (results.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = results[0];
    console.log(user);
    return res.json(user);
  } catch (err) {
    console.error("Database error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// updates user's information in database
app.post("/profile", async (req, res) => {
  const {
    user_id,
    username,
    password,
    first_name,
    last_name,
    email,
    street,
    city,
    state,
    postal_code,
  } = req.body;

  try {
    let query;
    let values;

    if (password) {
      const hashedPassword = await bcrypt.hash(password, saltRounds);
      query = `
        UPDATE users
        SET username=?, password=?, first_name=?, last_name=?, email=?, street=?, city=?, state=?, postal_code=?
        WHERE user_id=?
      `;
      values = [
        username,
        hashedPassword,
        first_name,
        last_name,
        email,
        street,
        city,
        state,
        postal_code,
        user_id,
      ];
    } else {
      query = `
        UPDATE users
        SET username=?, first_name=?, last_name=?, email=?, street=?, city=?, state=?, postal_code=?
        WHERE user_id=?
      `;
      values = [
        username,
        first_name,
        last_name,
        email,
        street,
        city,
        state,
        postal_code,
        user_id,
      ];
    }

    const [result] = await db.query(query, values);

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    console.log("Profile successfully updated.");
    res.json({ message: "Profile updated successfully" });
  } catch (err) {
    console.error("Error updating user:", err);
    res.status(500).json({ error: "Failed to update profile." });
  }
});

// deletes user from database
app.delete("/delete-user/:user_id", async (req, res) => {
  const { user_id } = req.params;

  try {
    await db.query("DELETE FROM users WHERE user_id = ?", [user_id]);

    console.log("Profile successfully deleted.");
    res.json({ message: "Profile successfully deleted." });
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "Profile deletion failed." });
  }
});

// listener
app.listen(PORT, () => {
  console.log(`Microservice-B server listening on port ${PORT}`);
});

module.exports.db = db;
