const express = require("express");
const db = require("./db");
const session = require("express-session");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const app = express();
const path = require("path");
const multer = require("multer");
const fs = require("fs");
require("dotenv").config();

const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Multer Storage Konfiguration
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadDir = path.join(__dirname, "public", "uploads");
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
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

// Generiere Verification Code
function generateVerificationCode() {
  return crypto.randomInt(100000, 999999).toString();
}

// Sende Verification Email
async function sendVerificationEmail(email, code, username) {
  const mailOptions = {
    from: `"Insyte" <${process.env.EMAIL}>`,
    to: email,
    subject: `Your Verification Code is ${code}`,
    html: `
    <div
      style="height: 98%; font-family: Arial, sans-serif; max-width: 500px; padding: 20px; border: 1px solid #ddd; border-radius: 10px; background-color: #f9f9f9;">
      <h2 style="color: #333; text-align: center;">Your Verification Code</h2>
      <p style="font-size: 16px; color: #555;">Hello, ${username}</p>
      <p style="font-size: 16px; color: #555;">Here is your verification code:</p>
      <div style="width: 100%; display: flex; justify-content: center; align-items: center;">
        <div
          style="text-align: center; font-size: 24px; font-weight: bold; color: #007bff; padding: 10px; border: 2px dashed #007bff; display: inline-block; margin: 10px 0;">
          ${code}
        </div>
      </div>
      <p style="font-size: 16px; color: #555;">This code will expire in <strong>10 minutes</strong>.</p>
      <p style="font-size: 16px; color: #555;">If you did not request this code, please ignore this email.</p>
      <p style="font-size: 16px; color: #555;">Best regards,</p>
      <p style="font-size: 16px; color: #555; font-weight: bold;">Your Insyte Team</p>
    </div>`,
  };

  return transporter.sendMail(mailOptions);
}

// Passwort-Hashing Funktion
async function hashPassword(password) {
  const saltRounds = 10;
  return await bcrypt.hash(password, saltRounds);
}

// Passwort-Vergleich Funktion
async function comparePassword(plainPassword, hashedPassword) {
  return await bcrypt.compare(plainPassword, hashedPassword);
}

app.set("view engine", "ejs");

// Session Middleware
app.use(
  session({
    secret: "mein-geheimes-session-schlüssel",
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
    return next();
  }
  res.redirect("/login");
};

// Signup Route - First Step (Generate and Send Verification Code)
app.post("/signup-request", async (req, res) => {
  const { username, mail, password } = req.body;

  // Überprüfen, ob die E-Mail bereits existiert
  db.get("SELECT * FROM users WHERE mail = ?", [mail], async (err, row) => {
    if (err) {
      return res.status(500).json({ error: "Fehler bei der Registrierung." });
    }

    if (row) {
      return res
        .status(400)
        .json({ error: "Diese E-Mail wird bereits verwendet." });
    }

    // Überprüfen, ob der Benutzername bereits existiert
    db.get(
      "SELECT * FROM users WHERE username = ?",
      [username],
      async (err, row) => {
        if (err) {
          return res
            .status(500)
            .json({ error: "Fehler bei der Registrierung." });
        }

        if (row) {
          return res
            .status(400)
            .json({ error: "Dieser Benutzername wird bereits verwendet." });
        }

        // Generate verification code
        const verificationCode = generateVerificationCode();

        try {
          // Send verification email
          await sendVerificationEmail(mail, verificationCode, username);

          // Store temporary signup data and verification code
          req.session.signupData = { username, mail, password };
          req.session.verificationCode = verificationCode;
          req.session.verificationExpiry = Date.now() + 10 * 60 * 1000; // 10 minutes

          res.status(200).json({ message: "Verification code sent" });
        } catch (emailError) {
          console.error("Email sending error:", emailError);
          res
            .status(500)
            .json({ error: "Fehler beim Senden der Verification Email." });
        }
      }
    );
  });
});

// Verification Route - Second Step
app.post("/verify-signup", async (req, res) => {
  const { code } = req.body;
  const { signupData, verificationCode, verificationExpiry } = req.session;

  // Check if signup data exists
  if (!signupData || !verificationCode) {
    return res
      .status(400)
      .json({ error: "Keine Registrierungsdaten gefunden." });
  }

  // Check if code is expired
  if (Date.now() > verificationExpiry) {
    delete req.session.signupData;
    delete req.session.verificationCode;
    delete req.session.verificationExpiry;
    return res.status(400).json({ error: "Verification Code abgelaufen." });
  }

  // Verify the code
  if (code !== verificationCode) {
    return res.status(400).json({ error: "Ungültiger Verification Code." });
  }

  try {
    // Hash the password
    const hashedPassword = await hashPassword(signupData.password);

    // Insert user into database
    db.run(
      "INSERT INTO users (username, mail, password) VALUES (?, ?, ?)",
      [signupData.username, signupData.mail, hashedPassword],
      (err) => {
        if (err) {
          console.error("Fehler beim Speichern in der Datenbank:", err.message);
          return res
            .status(500)
            .json({ error: "Fehler bei der Registrierung." });
        }

        // Clear session data
        delete req.session.signupData;
        delete req.session.verificationCode;
        delete req.session.verificationExpiry;

        res.status(200).json({ message: "Registrierung erfolgreich" });
      }
    );
  } catch (hashError) {
    console.error("Fehler beim Hashing des Passworts:", hashError.message);
    res.status(500).json({ error: "Fehler bei der Registrierung." });
  }
});

// Existing routes from previous implementation
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
    res.redirect("/");
  } else {
    res.sendFile(path.join(__dirname, "public", "signup.html"));
  }
});

app.get("/login", (req, res) => {
  if (req.session.loggedIn) {
    res.redirect("/");
  } else {
    res.sendFile(path.join(__dirname, "public", "login.html"));
  }
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

        if (req.file) {
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

          profileeImagePath = `/uploads/${req.file.filename}`;
        }

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

app.get("/allprofile", isAuthenticated, (req, res) => {
  db.all("SELECT * FROM users", (err, rows) => {
    if (err) {
      console.error("Fehler bei der Datenbankabfrage:", err.message);
      return res.status(500).send("Fehler beim Laden der Profile.");
    }

    if (rows.length === 0) {
      return res.status(404).send("Keine Benutzer gefunden.");
    }

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

app.listen(3000, () => {
  console.log("Server läuft auf http://localhost:3000");
});
