const express = require("express");
const db = require("./db");
const session = require("express-session");
const bcrypt = require("bcrypt");
const app = express();
const path = require("path");
const multer = require("multer"); // Multer für Datei-Uploads
const fs = require("fs"); // Für Dateisystem-Operationen
const { name } = require("ejs");

// Multer Storage Konfiguration
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    // Stelle sicher, dass der Zielordner existiert
    const uploadDir = path.join(__dirname, "public", "uploads");
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    // Einzigartige Dateinamen generieren
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    const fileExt = path.extname(file.originalname);
    cb(null, "profile-" + uniqueSuffix + fileExt);
  },
});

// Multer Upload Konfiguration
const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB Limit
  fileFilter: (req, file, cb) => {
    // Überprüfen auf erlaubte Bildtypen
    const filetypes = /jpeg|jpg|png|gif/;
    const mimetype = filetypes.test(file.mimetype);
    const extname = filetypes.test(
      path.extname(file.originalname).toLowerCase()
    );

    if (mimetype && extname) {
      return cb(null, true);
    }
    cb(new Error("Nur Bilder im Format jpeg, jpg, png und gif sind erlaubt!"));
  },
});

// Passwort-Hashing Funktion
async function hashPassword(password) {
  const saltRounds = 10;
  return await bcrypt.hash(password, saltRounds);
}

// Passwort-Vergleich Funktion
async function comparePassword(plainPassword, hashedPassword) {
  return await bcrypt.compare(plainPassword, hashedPassword);
}

app.set("view engine", "ejs"); // EJS als View-Engine setzen

// Session Middleware
app.use(
  session({
    secret: "mein-geheimes-session-schlüssel", // Verwende einen sicheren, zufälligen Wert in einer echten Anwendung
    resave: false,
    saveUninitialized: true,
  })
);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// Login-Prüfung Middleware
const isAuthenticated = (req, res, next) => {
  if (req.session.loggedIn) {
    console.log(req.session.loggedIn);
    return next(); // Benutzer ist eingeloggt, weiter zur nächsten Middleware/Route
  }
  res.redirect("/login"); // Benutzer ist nicht eingeloggt, weiter zur Login-Seite
};

// endpoints
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/users", isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "users.html"));
});

app.get("/profiledata", isAuthenticated, (req, res) => {
  const userId = req.session.userId;

  db.get("SELECT * FROM users WHERE user_id = ?", [userId], (err, row) => {
    if (err) {
      console.error("Fehler bei der Datenbankabfrage:", err.message);
      return res.status(500).send("Fehler beim Laden des profiles.");
    }

    if (!row) {
      return res.status(404).send("Benutzer nicht gefunden.");
    }

    // Rückgabe der Benutzerdaten als JSON
    res.json({
      username: row.username,
      bio: row.bio,
      profileeImage: row.profilee_image,
      name: row.name,
    });
  });
});

app.get("/profile", isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "profile.html"));
});

app.get("/signup", (req, res) => {
  if (req.session.loggedIn) {
    console.log(req.session.loggedIn);
    res.redirect("/");
  } else {
    res.sendFile(path.join(__dirname, "public", "signup.html"));
  }
});

app.get("/login", (req, res) => {
  if (req.session.loggedIn) {
    console.log(req.session.loggedIn);
    res.redirect("/");
  } else {
    res.sendFile(path.join(__dirname, "public", "login.html"));
  }
});

app.post("/signup", async (req, res) => {
  const { username, mail, password } = req.body;

  // Überprüfen, ob die E-Mail bereits existiert
  db.get("SELECT * FROM users WHERE mail = ?", [mail], async (err, row) => {
    if (err) {
      console.error("Fehler bei der Datenbankabfrage:", err.message);
      return res.status(500).send("Fehler bei der Registrierung.");
    }

    if (row) {
      return res.status(400).send("Diese E-Mail wird bereits verwendet.");
    }

    // Überprüfen, ob der Benutzername bereits existiert
    db.get(
      "SELECT * FROM users WHERE username = ?",
      [username],
      async (err, row) => {
        if (err) {
          console.error("Fehler bei der Datenbankabfrage:", err.message);
          return res.status(500).send("Fehler bei der Registrierung.");
        }

        if (row) {
          return res
            .status(400)
            .send("Dieser Benutzername wird bereits verwendet.");
        }

        try {
          const hashedPassword = await hashPassword(password);

          db.run(
            "INSERT INTO users (username, mail, password) VALUES (?, ?, ?)",
            [username, mail, hashedPassword],
            (err) => {
              if (err) {
                console.error(
                  "Fehler beim Speichern in der Datenbank:",
                  err.message
                );
                return res.status(500).send("Fehler bei der Registrierung.");
              }
              res.redirect("/login");
            }
          );
        } catch (hashError) {
          console.error(
            "Fehler beim Hashing des Passworts:",
            hashError.message
          );
          res.status(500).send("Fehler bei der Registrierung.");
        }
      }
    );
  });
});

app.post("/login", (req, res) => {
  const { mail, password } = req.body;

  db.get("SELECT * FROM users WHERE mail = ?", [mail], async (err, row) => {
    if (err) {
      console.error("Fehler bei der Datenbankabfrage:", err.message);
      return res.status(500).send("Fehler bei der Anmeldung.");
    }

    if (!row) {
      return res.status(400).send("Diese E-Mail ist nicht registriert.");
    }

    try {
      const isMatch = await comparePassword(password, row.password);

      if (isMatch) {
        // Session setzen, dass der Benutzer eingeloggt ist
        req.session.loggedIn = true;
        req.session.userId = row.user_id;
        res.redirect("/profile");
      } else {
        res.status(400).send("Falsches Passwort.");
      }
    } catch (compareError) {
      console.error("Fehler beim Passwortvergleich:", compareError.message);
      res.status(500).send("Fehler bei der Anmeldung.");
    }
  });
});

app.post(
  "/update-profile",
  isAuthenticated,
  upload.single("profileimg"),
  (req, res) => {
    const userId = req.session.userId;
    const { name, bio } = req.body;

    // Bestehende Benutzerprofilebild-Informationen abrufen
    db.get(
      "SELECT profilee_image FROM users WHERE user_id = ?",
      [userId],
      (err, row) => {
        if (err) {
          console.error(
            "Fehler beim Abrufen der Benutzerinformationen:",
            err.message
          );
          return res
            .status(500)
            .send("Fehler beim Aktualisieren des profiles.");
        }

        let profileeImagePath = row ? row.profilee_image : null;

        // Wenn ein neues Bild hochgeladen wurde, altes löschen und Pfad aktualisieren
        if (req.file) {
          // Altes profilebild löschen, wenn es existiert und nicht das Standard-Bild ist
          if (
            profileeImagePath &&
            profileeImagePath !== "default-profilee.png"
          ) {
            const oldImagePath = path.join(
              __dirname,
              "public",
              profileeImagePath
            );
            if (fs.existsSync(oldImagePath)) {
              fs.unlinkSync(oldImagePath);
            }
          }

          // Relativer Pfad für die Datenbank
          profileeImagePath = `/uploads/${req.file.filename}`;
        }

        // Datenbank aktualisieren
        db.run(
          "UPDATE users SET name = ?, bio = ?, profilee_image = ? WHERE user_id = ?",
          [name, bio, profileeImagePath, userId],
          (updateErr) => {
            if (updateErr) {
              console.error(
                "Fehler beim Aktualisieren der Datenbank:",
                updateErr.message
              );
              return res
                .status(500)
                .send("Fehler beim Aktualisieren des profiles.");
            }

            // Nach erfolgreichem Update zur profileseite weiterleiten
            res.redirect("/profile");
          }
        );
      }
    );
  }
);

app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send("Fehler beim Abmelden.");
    }
    res.redirect("/login");
  });
});

app.listen(3000, () => {
  console.log("Server läuft auf http://localhost:3000");
});

app.get("/allprofile", isAuthenticated, (req, res) => {
  db.all("SELECT * FROM users", (err, rows) => {
    if (err) {
      console.error("Fehler bei der Datenbankabfrage:", err.message);
      return res.status(500).send("Fehler beim Laden der Profile.");
    }

    if (rows.length === 0) {
      return res.status(404).send("Keine Benutzer gefunden.");
    }

    // Rückgabe der Benutzerdaten als JSON
    res.json(
      rows.map((row) => ({
        username: row.username,
        bio: row.bio,
        profileeImage: row.profilee_image,
        name: row.name,
      }))
    );
  });
});
