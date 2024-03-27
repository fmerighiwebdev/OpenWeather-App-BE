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

import { signUp, findUserByEmail, findUserById } from "./server-utils.js";

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
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());
app.use(cors());

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  const user = findUserById(id);
  done(null, user);
});

passport.use(
  "local",
  new LocalStrategy(
    { usernameField: "email", passwordField: "password" },
    async (email, password, done) => {
      const user = await findUserByEmail(email);
      if (!user) {
        return done(null, false);
      }
      if (!bcrypt.compareSync(password, user.password)) {
        return done(null, false);
      }
      return done(null, user);
    }
  )
);

passport.use(
  "jwt",
  new JWTStrategy.Strategy(
    {
      jwtFromRequest: JWTStrategy.ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: process.env.JWT_SECRET,
    },
    (payload, done) => {
      try {
        const user = findUserById(payload.user.id);
        if (!user) {
          return done(null, false);
        }
        return done(null, user);
      } catch (error) {
        return done(error, false);
      }
    }
  )
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

app.post("/api/login", passport.authenticate("local"), (req, res) => {
  const token = jwt.sign({ user: req.user }, process.env.JWT_SECRET, { expiresIn: "1h" });
  res.status(200).json({ token: token });
});

app.get("/api/user", passport.authenticate("jwt"), (req, res) => {
  res.status(200).json({ user: req.user });
});

app.get("/api/logout", (req, res) => {
  req.logout();
  res.status(200).json({ message: "Logout effettuato con successo" });
});

app.get("/api/validateToken", passport.authenticate("jwt", { session: false }), (req, res) => {
  try {
    res.status(200).json({ message: "Token valido" });
  } catch (error) {
    res.status(401).json({ message: "Token non valido" });
  }
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
