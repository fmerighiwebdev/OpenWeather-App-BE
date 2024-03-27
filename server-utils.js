import db from "./index.js";

async function signUp(name, username, email, hashedPassword) {
  try {
    await db.query(
      "INSERT INTO users (name, username, email, password) VALUES ($1, $2, $3, $4)",
      [name, username, email, hashedPassword]
    );
  } catch (error) {
    console.error("Errore nella registrazione: ", error);
  }
}

async function findUserByEmail(email) {
  try {
    const user = await db.query("SELECT * FROM users WHERE email = $1", [email]);
    return user.rows[0];
  } catch (error) {
    console.error("Errore nella ricerca dell'utente: ", error);
  }
}

async function findUserById(id) {
  try {
    const user = await db.query("SELECT * FROM users WHERE id = $1", [id]);
    return user.rows[0];
  } catch (error) {
    console.error("Errore nella ricerca dell'utente: ", error);
  }
}

export { signUp, findUserByEmail, findUserById };
