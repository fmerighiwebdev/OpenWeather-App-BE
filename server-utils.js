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

export { signUp };
