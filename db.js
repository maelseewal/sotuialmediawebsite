const sqlite3 = require("sqlite3").verbose();

const db = new sqlite3.Database("./users.db", (err) => {
  if (err) {
    console.error("Fehler beim Öffnen der Datenbank:", err.message);
  } else {
    console.log("Verbindung zur SQLite-Datenbank hergestellt.");

    // Erstellen der 'users'-Tabelle
    db.run(
      `CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        mail TEXT UNIQUE,
        password TEXT,
        bio TEXT,
        name TEXT,
        profile_image BLOB  /* Changed from TEXT to BLOB */
      )`,
      (err) => {
        if (err) {
          console.error(
            "Fehler beim Erstellen der Tabelle 'users':",
            err.message
          );
        } else {
          console.log("Tabelle 'users' ist bereit.");
        }
      }
    );

    // Erstellen der 'followers'-Tabelle
    db.run(
      `CREATE TABLE IF NOT EXISTS followers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        follower_id INTEGER NOT NULL,   -- Der User, der folgt
        following_id INTEGER NOT NULL,  -- Der User, dem gefolgt wird
        FOREIGN KEY (follower_id) REFERENCES users(user_id) ON DELETE CASCADE,
        FOREIGN KEY (following_id) REFERENCES users(user_id) ON DELETE CASCADE,
        UNIQUE(follower_id, following_id)  -- Verhindert doppelte Einträge
      )`,
      (err) => {
        if (err) {
          console.error(
            "Fehler beim Erstellen der Tabelle 'followers':",
            err.message
          );
        } else {
          console.log("Tabelle 'followers' ist bereit.");
        }
      }
    );
  }
});

module.exports = db;
