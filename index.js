import express from "express";
import dotenv from "dotenv";
import pg from "pg";
import passport from "passport";
import session from "express-session";
import LocalStrategy from "passport-local";
import JWTStrategy from "passport-jwt";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

import { signUp } from "./server-utils.js";

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "openweather-app",
  password: process.env.DB_PW,
  port: 5432,
});
export default db;

try {
  db.connect();
  console.log("Database connected");
} catch (error) {
  console.error("Database connection failed");
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({ 
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(cors());

passport.use(
  new LocalStrategy((email, password, done) => {
    try {
      const user = db.query("SELECT * FROM users WHERE email = $1", [email]);
      if (!user) {
        return done(null, false, { message: "Incorrect email" });
      }
      if (user.password !== password) {
        return done(null, false, { message: "Incorrect password" });
      }
      return done(null, user);
    } catch (error) {
      return done(error);
    }
  })
);

app.post("/api/signup", (req, res) => {
  const { name, username, email, password } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 10);

  try {
    signUp(name, username, email, hashedPassword);
    res.status(201).json({ message: "Utente creato con successo" });
  } catch (error) {
    res.status(500).json({ message: "Errore nella creazione utente" });
  }
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
