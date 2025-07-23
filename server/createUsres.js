require("dotenv").config();
const mysql = require("mysql2");
const bcrypt = require("bcrypt");

// ➕ Admin kullanıcı bilgileri
const username = "admin";
const email = "admin@example.com";
const plainPassword = "admin1234";
const role = "admin";

// 🔌 Veritabanı bağlantısı
const db = mysql.createConnection({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "SP",
});

db.connect(async (err) => {
  if (err) {
    console.error("❌ Veritabanı bağlantı hatası:", err.message);
    return;
  }
  console.log("✅ Veritabanına bağlanıldı.");

  try {
    const hashedPassword = await bcrypt.hash(plainPassword, 10);

    const insertUserQuery = `
      INSERT INTO users (username, password, email, role)
      VALUES (?, ?, ?, ?)
    `;

    db.query(
      insertUserQuery,
      [username, hashedPassword, email, role],
      (userErr, userResults) => {
        if (userErr) {
          console.error("❌ users tablosuna ekleme hatası:", userErr.message);
          db.end();
          return;
        }

        console.log("✅ users tablosuna eklendi.");
        const userId = userResults.insertId;

        const insertAdminQuery = `
          INSERT INTO adminUsers (id, username, password, email, role)
          VALUES (?, ?, ?, ?, ?)
        `;

        db.query(
          insertAdminQuery,
          [userId, username, hashedPassword, email, role],
          (adminErr, adminResults) => {
            if (adminErr) {
              console.error(
                "❌ adminUsers tablosuna ekleme hatası:",
                adminErr.message
              );
            } else {
              console.log("✅ adminUsers tablosuna eklendi.");
            }
            db.end();
          }
        );
      }
    );
  } catch (err) {
    console.error("❌ Şifre hashlenirken hata:", err.message);
    db.end();
  }
});
