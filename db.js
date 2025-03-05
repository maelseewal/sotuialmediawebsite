const sqlite3 = require("sqlite3").verbose();

const db = new sqlite3.Database("./users.db", (err) => {
  if (err) {
    console.error("Fehler beim Öffnen der Datenbank:", err.message);
  } else {
    console.log("Verbindung zur SQLite-Datenbank hergestellt.");

    db.run(
      `CREATE TABLE IF NOT EXISTS users (
  user_id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT,
  mail TEXT UNIQUE,
  password TEXT,
  bio TEXT,
  name TEXT,
  profilee_image TEXT
)`,
      (err) => {
        if (err) {
          console.error("Fehler beim Erstellen der Tabelle:", err.message);
        } else {
          console.log("Tabelle 'users' ist bereit.");
        }
      }
    );
  }
});

module.exports = db;
