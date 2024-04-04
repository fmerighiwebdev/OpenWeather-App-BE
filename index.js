import express from "express";
import dotenv from "dotenv";
import pg from "pg";
import passport from "passport";
import session from "express-session";
import JWTStrategy from "passport-jwt";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

import {
  signUp,
  findUserByEmail,
  findUserById,
  insertFavourite,
  removeFavourite,
  getFavourites,
} from "./server-utils.js";

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

passport.deserializeUser(async (id, done) => {
  try {
    const user = await findUserById(id);
    if (user) {
      done(null, user);
    } else {
      done(new Error("User not found"));
    }
  } catch (error) {
    done(error);
  }
});

passport.use(
  "jwt",
  new JWTStrategy.Strategy(
    {
      jwtFromRequest: JWTStrategy.ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: process.env.JWT_SECRET,
    },
    async (payload, done) => {
      try {
        const user = await findUserById(payload.user.id);
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

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await findUserByEmail(email);
    console.log(user);
    if (!user) {
      return res.status(404).json({ message: "Utente non trovato" });
    }

    if (bcrypt.compareSync(password, user.password)) {
      const token = jwt.sign({ user }, process.env.JWT_SECRET, {
        expiresIn: "1h",
      });
      return res.status(200).json({ token });
    } else {
      return res.status(401).json({ message: "Credenziali non valide" });
    }
  } catch (error) {
    return res.status(500).json({ message: "Errore nel login" });
  }
});

app.get("/api/logout", passport.authenticate("jwt"), (req, res) => {
  req.logout((err) => {
    if (err) {
      return res.status(500).json({ message: "Errore nel logout" });
    }
  });
  res.status(200).json({ message: "Logout effettuato con successo" });
});

app.post("/api/addFavourite", passport.authenticate("jwt"), (req, res) => {
  const { city } = req.body;

  try {
    insertFavourite(city, req.user.id);
    res.status(201).json({ message: "Città aggiunta ai preferiti" });
  } catch (error) {
    res.status(500).json({ message: "Errore nell'aggiunta della città" });
  }
});

app.delete("/api/removeFavourite/:id", passport.authenticate("jwt"), (req, res) => {
  const { id } = req.params;

  try {
    removeFavourite(id);
    res.status(200).json({ message: "Città rimossa dai preferiti" });
  } catch (error) {
    res.status(500).json({ message: "Errore nella rimozione della città" });
  }
});

app.get(
  "/api/getFavourites",
  passport.authenticate("jwt"),
  async (req, res) => {
    try {
      const favourites = await getFavourites(req.user.id);
      res.status(200).json(favourites);
    } catch (error) {
      res.status(500).json({ message: "Errore nella ricerca dei preferiti" });
    }
  }
);

app.get(
  "/api/validateToken",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    try {
      res.status(200).json({ message: "Token valido", user: req.user });
    } catch (error) {
      res.status(401).json({ message: "Token non valido" });
    }
  }
);

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
