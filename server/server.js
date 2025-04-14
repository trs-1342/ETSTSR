require("dotenv").config();
const express = require("express");
const session = require("express-session");
const cors = require("cors");
const mysql = require("mysql2");
const WebSocket = require("ws");
const http = require("http");
const bcrypt = require("bcrypt");
const app = express();
const PORT = 2431;
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const { exec } = require("child_process");
const path = require("path");
const bodyParser = require("body-parser");
const PDFDocument = require("pdfkit");
const printerForPdf = require("pdf-to-printer");
const util = require("util");
const os = require("os");
const QRCode = require("qrcode");
const fs = require("fs");

app.use(express.json());
app.use(bodyParser.json());

const DB_TABLE_NAME = process.env.DB_TABLE_NAME;

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "password",
  database: "ETSTSR",
  port: 3306,
});

const dbQuery = util.promisify(db.query).bind(db);

db.connect((err) => {
  if (err) {
    console.error("MySQL bağlantı hatası:", err);
    return;
  }
  console.log("MySQL");
});

app.use(
  session({
    secret: "superSecureRandomSecretKey123!",
    resave: false,
    saveUninitialized: true,
    rolling: false,
    cookie: {
      maxAge: 43200000,
      sameSite: "lax",
      secure: false,
    },
  })
);

const ALLOWED_ORIGINS = [
  "http://192.168.0.201",
  "http://192.168.0.201:80",
  "http://192.168.0.201:2431",
];

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true);

      // Bazı tarayıcılar origin'i port belirtmeden gönderebilir
      const normalizedOrigin = origin.replace(/:\d+$/, "");

      if (
        ALLOWED_ORIGINS.includes(origin) ||
        ALLOWED_ORIGINS.includes(normalizedOrigin)
      ) {
        callback(null, true);
      } else {
        console.warn(`⛔ CORS engellendi: ${origin}`);
        callback(null, false);
      }
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.header("Access-Control-Allow-Origin", origin);
    res.header("Access-Control-Allow-Credentials", "true");
    res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
    res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  }
  next();
});

wss.on("connection", (ws, req) => {
  sessionParser(req, {}, () => {
    const user = req.session?.user;
    if (user) {
      console.log("WebSocket kullanıcı:", user.username);
      ws.send(JSON.stringify({ message: "Yetkili erişim sağlandı.", user }));
    } else {
      ws.send(JSON.stringify({ message: "Yetkisiz erişim!" }));
      ws.close();
    }
  });

  const user = req.session?.user;

  if (user) {
    console.log("Yetkili kullanıcı bağlantı sağladı:", user.username);

    ws.send(
      JSON.stringify({
        type: "user",
        message: "Yetkili erişim sağlandı.",
        user: {
          username: user.username,
          role: user.role,
          isAdmin: user.role,
        },
      })
    );
  } else {
    ws.send(
      JSON.stringify({
        type: "error",
        message: "Yetkisiz erişim! Lütfen giriş yapın.",
      })
    );
    ws.close();
    return;
  }

  ws.on("message", (message) => {
    try {
      const parsedMessage = JSON.parse(message);

      if (parsedMessage.type === "fetchRecords") {
        const query = `
          SELECT *,
          IFNULL(DATE_FORMAT(HazirlamaTarihi, '%Y-%m-%d %H:%i:%s'), '') AS HazirlamaTarihi,
          IFNULL(DATE_FORMAT(TeslimEtmeTarihi, '%Y-%m-%d %H:%i:%s'), '') AS TeslimEtmeTarihi
          FROM records
        `;

        db.query(query, (err, results) => {
          if (err) {
            console.error("Veritabanı hatası:", err.message);
            ws.send(
              JSON.stringify({
                type: "error",
                message: "Veritabanından kayıtlar çekilemedi.",
              })
            );
            return;
          }

          ws.send(
            JSON.stringify({
              type: "records",
              data: results,
            })
          );
        });
      }
    } catch (err) {
      console.error("Mesaj ayrıştırma hatası:", err.message);
      ws.send(
        JSON.stringify({
          type: "error",
          message: "Geçersiz JSON formatı.",
        })
      );
    }
  });

  ws.on("close", () => {
    console.log("WebSocket bağlantısı kapatıldı.");
  });

  ws.on("error", (error) => {
    console.error("WebSocket Hatası:", error.message);
  });
});

function authMiddleware(req, res, next) {
  const clientIP = req.headers.origin || req.headers.referer || req.ip; // istemci IP'sini al

  if (!ALLOWED_ORIGINS.includes(clientIP)) {
    return res.status(403).json({ message: "Erişim reddedildi." });
  }

  if (!req.session || !req.session.user) {
    return res.status(401).json({ message: "Unauthorized access!" });
  }

  const user = req.session.user;
  req.user = {
    username: user.username,
    role: user.role,
    isAdmin: user.role === "admin",
  };
  next();
}

const formatDateForMySQL = (isoDate) => {
  if (!isoDate) return null; // Boş veya undefined değerler null döner

  const date = new Date(isoDate);

  // Geçerli tarih olup olmadığını kontrol et
  if (isNaN(date.getTime())) {
    // console.warn(`Geçersiz tarih değeri: ${isoDate}`);
    return null;
  }

  // YYYY-MM-DD HH:MM:SS formatına çevir
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  const hours = String(date.getHours()).padStart(2, "0");
  const minutes = String(date.getMinutes()).padStart(2, "0");
  const seconds = String(date.getSeconds()).padStart(2, "0");

  return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
};

app.use(
  "/pdfs",
  express.static(path.join(os.homedir(), "Desktop", "enigma-pdfs"))
);

app.post("/api-client/sorgula", (req, res) => {
  const { adSoyad, fishNo } = req.body;

  if (!adSoyad || !fishNo) {
    return res.status(400).json({ error: "Ad Soyad ve Fish No gerekli!" });
  }

  if (!DB_TABLE_NAME) {
    console.error("Veritabanı tablo adı tanımlı değil!");
    return res
      .status(500)
      .json({ error: "Server hatası! Lütfen yöneticinize bildirin." });
  }

  // ✅ SQL Injection'dan korunmak için `db.format()` kullan
  const query = db.format(`SELECT * FROM ?? WHERE AdSoyad = ? AND fishNo = ?`, [
    DB_TABLE_NAME,
    adSoyad,
    fishNo,
  ]);

  db.query(query, (err, results) => {
    if (err) {
      console.error("MySQL Hatası:", err);
      return res.status(500).json({ error: "Veritabanı hatası!" });
    }

    if (results.length > 0) {
      res.json({ success: true, record: results[0] });
    } else {
      res.status(404).json({ success: false, error: "Kayıt bulunamadı!" });
    }
  });
});

app.post("/api-client/sorgula-qr", (req, res) => {
  const { fishNo } = req.body;

  if (!fishNo) {
    return res.status(400).json({ error: "Fish No gerekli!" });
  }

  if (!DB_TABLE_NAME) {
    console.error("❌ Veritabanı tablo adı `.env` içinde tanımlı değil!");
    return res
      .status(500)
      .json({ error: "Server hatası! Lütfen yöneticinize bildirin." });
  }

  // ✅ SQL Injection'dan korunmak için `db.format()` kullan
  const query = db.format(`SELECT * FROM ?? WHERE fishNo = ?`, [
    DB_TABLE_NAME,
    fishNo,
  ]);

  db.query(query, (err, results) => {
    if (err) {
      console.error("❌ MySQL Hatası:", err);
      return res.status(500).json({ error: "Veritabanı hatası!" });
    }

    if (results.length > 0) {
      res.json({ success: true, record: results[0] });
    } else {
      res.status(404).json({ success: false, error: "Kayıt bulunamadı!" });
    }
  });
});

app.get("/api-client/qr-sorgula", (req, res) => {
  const fishNo = req.query.fishNo;

  if (!fishNo) {
    return res.redirect(`http://192.168.0.201:80/`); // ❌ Eğer fishNo yoksa anasayfaya yönlendir
  }

  if (!DB_TABLE_NAME) {
    console.error("❌ Veritabanı tablo adı `.env` içinde tanımlı değil!");
    return res.redirect(`http://192.168.0.201:80/`);
  }

  // ✅ SQL Injection'dan korunmak için `db.format()` kullan
  const query = db.format(`SELECT * FROM ?? WHERE fishNo = ?`, [
    DB_TABLE_NAME,
    fishNo,
  ]);

  db.query(query, (err, results) => {
    if (err) {
      console.error("❌ MySQL Hatası:", err);
      return res.redirect(`http://192.168.0.201/`);
    }

    if (results.length > 0) {
      const userRecord = JSON.stringify(results[0]);

      // ✅ Kullanıcı bulunduysa, bilgileri URL parametresi olarak ekleyerek yönlendir
      res.redirect(
        `http://192.168.0.201:80/client?record=${encodeURIComponent(userRecord)}`
      );
    } else {
      res.redirect(`http://192.168.0.201:80/`); // ❌ Kullanıcı yoksa anasayfaya yönlendir
    }
  });
});

app.get("/api/printers", (req, res) => {
  let command;

  if (process.platform === "win32") {
    // 🔥 Windows'ta ağ ve USB yazıcıları almak için iki komut kullanıyoruz
    command =
      'powershell -command "Get-Printer | Select-Object Name, PortName" || "wmic printer get Name,PortName"';
  } else if (process.platform === "linux") {
    command = "lpstat -v"; // Linux için bağlı yazıcıları listeler
  } else if (process.platform === "darwin") {
    command = "lpstat -v"; // macOS için
  } else {
    return res.status(500).json({ error: "Desteklenmeyen işletim sistemi" });
  }

  exec(command, (error, stdout) => {
    if (error) {
      console.error("Yazıcıları listelerken hata oluştu:", error);
      return res.status(500).json({ error: "Yazıcılar listelenemedi." });
    }

    const printers = stdout
      .trim()
      .split("\n")
      .map((line) => line.trim());

    let detectedPrinters = [];

    if (process.platform === "win32") {
      // Windows çıktısını işleyerek ağ veya USB olduğunu belirle
      detectedPrinters = printers.map((line) => {
        const parts = line.split(/\s{2,}/);
        const printerName = parts[0] || "";
        const portName = parts[1] || "";

        // 🔥 USB, COM, LPT, WSD veya TCP/IP bağlantılarını ayır
        let type = "Bilinmeyen Bağlantı";
        if (portName.startsWith("USB") || portName.includes("DOT4")) {
          type = "Kablolu (USB)";
        } else if (portName.startsWith("LPT")) {
          type = "Kablolu (LPT Paralel Port)";
        } else if (portName.startsWith("COM")) {
          type = "Kablolu (Seri Port - COM)";
        } else if (portName.startsWith("WSD") || portName.startsWith("TCP")) {
          type = "Ağ (Network)";
        }

        return { name: printerName, type };
      });
    } else if (process.platform === "linux" || process.platform === "darwin") {
      // Linux ve macOS çıktısını işle
      detectedPrinters = printers.map((line) => {
        const printerName = line
          .split(":")[0]
          .replace("device for ", "")
          .trim();
        let type = "Bilinmeyen Bağlantı";

        if (line.includes("usb")) {
          type = "Kablolu (USB)";
        } else if (line.includes("network") || line.includes("ipp")) {
          type = "Ağ (Network)";
        }

        return { name: printerName, type };
      });
    }

    // console.log("Bağlı Yazıcılar:", detectedPrinters);
    res.json({ printers: detectedPrinters });
  });
});

app.post("/api/print", async (req, res) => {
  try {
    const {
      printerName: unPrinterName,
      fishNo,
      AdSoyad,
      date,
      TelNo,
      Urun,
      Marka,
      Model,
      SeriNo,
      GarantiDurumu,
      BirlikteAlinanlar,
      Aciklama,
      sorunlar,
      ucret,
      altMetin,
    } = req.body;

    if (!unPrinterName) {
      return res.status(400).json({ error: "Eksik parametre" });
    }

    let printerName = unPrinterName.replace(/ WSD-.+$/, "").trim();
    printerName = printerName.replace(/^"(.*)"$/, "$1");
    // console.log(`📨 Temizlenmiş Yazıcı Adı: "${printerName}"`);

    const pdfFilePath = path.join(
      os.homedir(),
      "Desktop/enigma-records",
      `${AdSoyad}_${fishNo}_${date}.pdf`
    );

    const doc = new PDFDocument({
      size: "A4",
      margins: { top: 10, left: 10, right: 10, bottom: 10 },
    });
    const writeStream = fs.createWriteStream(pdfFilePath);
    doc.pipe(writeStream);

    const fontPath = path.join(__dirname, "./fonts/DejaVuSans.ttf");
    if (fs.existsSync(fontPath)) {
      doc.font(fontPath);
    } else {
      console.warn(`⚠️ Font dosyası bulunamadı: ${fontPath}`);
    }

    // drawTicket fonksiyonunu asenkron hale getirerek, QR kodun oluşturulmasını bekliyoruz
    async function drawTicket(xOffset) {
      const qrCodePath = path.join(os.tmpdir(), `qr_${fishNo}.png`);

      // QR kod oluşturulmasını bekleyin
      await QRCode.toFile(
        qrCodePath,
        `http://192.168.0.201:2431/api-client/qr-sorgula?fishNo=${fishNo}`,
        { width: 20 }
      );

      // Ardından oluşturulan QR kod resmini PDF'e ekleyin
      doc.image("../client/public/logo.png", xOffset + 10, 0, { width: 90 });
      doc.image(qrCodePath, xOffset + 200, 0, { width: 90 });

      let yPos = 75;
      const leftColumn = [
        `Tarih: ${date}`,
        `Ad Soyad: ${AdSoyad}`,
        `Tel No: ${TelNo}`,
        `Ürün: ${Urun}`,
        `Marka: ${Marka}`,
        `Model: ${Model}`,
        `Seri No: ${SeriNo}`,
        `Garanti: ${GarantiDurumu}`,
        `Birlikte A.: ${BirlikteAlinanlar}`,
        `Açıklama: ${Aciklama}`,
      ];
      leftColumn.forEach((text) => {
        doc.fontSize(8).text(text, xOffset + 15, yPos);
        yPos += 10;
      });

      doc.fontSize(10).text(`Fiş No: ${fishNo}`, xOffset + 140, 85);
      doc
        .moveTo(xOffset + 140, 95)
        .lineTo(xOffset + 200, 95)
        .strokeColor("red")
        .stroke();

      doc.fontSize(8).text("Sorunlar:", xOffset + 140, 95);

      doc
        .fontSize(8)
        .text(
          sorunlar ? sorunlar.substring(0, 50) : "Belirtilmedi",
          xOffset + 140,
          105,
          {
            width: 100,
            height: 20,
          }
        );

      doc.fontSize(8).text(altMetin, xOffset + 10, 190, { width: 280 });
    }

    let tableY = 300;
    let colWidth = 40;
    xOffset = 0;
    for (let i = 1; i <= 8; i++) {
      doc.rect(xOffset + 10 + i * colWidth, tableY, colWidth, 20).stroke();

      doc.fontSize(8).text(fishNo, xOffset + 12 + i * colWidth, tableY + 6, {
        width: colWidth,
        align: "center",
      });
    }

    await drawTicket(0);
    await drawTicket(300);

    doc.end();

    writeStream.on("finish", async () => {
      try {
        console.log(`📨 Yazdırılıyor: ${printerName}, Dosya: ${pdfFilePath}`);
        await printerForPdf.print(pdfFilePath, { printer: printerName });
        res.json({ success: true, message: "Baskı başarılı" });
      } catch (err) {
        console.error("Baskı hatası:", err);
        res
          .status(500)
          .json({ error: "Baskı sırasında hata oluştu.", details: err });
      }
    });

    writeStream.on("error", (err) => {
      console.error("PDF oluşturma hatası:", err);
      res.status(500).json({ error: "PDF oluşturulamadı.", details: err });
    });
  } catch (error) {
    console.error("İşlem sırasında hata oluştu:", error);
    res.status(500).json({ error: "Sunucu hatası", details: error.message });
  }
});

app.post("/api/xprint", (req, res) => {
  const { printerName, printData } = req.body;

  if (!printerName) {
    return res.status(400).json({ error: "Yazıcı adı belirtilmedi." });
  }

  exec("wmic printer get Name", (error, stdout, stderr) => {
    if (error) {
      console.error(`Yazıcıları alırken hata: ${error.message}`);
      return res.status(500).json({ error: "Yazıcıları alırken hata oluştu." });
    }

    const printerList = stdout
      .split("\n")
      .slice(1)
      .map((name) => name.trim())
      .filter((name) => name);
    const xprinterExists = printerList.some((name) =>
      name.toLowerCase().includes("xprinter")
    );

    if (!xprinterExists) {
      return res
        .status(404)
        .json({ error: "Xprinter bulunamadı. Lütfen yazıcıyı kontrol edin." });
    }

    exec(
      `echo ${printData} > print_job.txt & print /D:\\${printerName} print_job.txt`,
      (printError, printStdout, printStderr) => {
        if (printError) {
          console.error(`Yazdırma hatası: ${printError.message}`);
          return res
            .status(500)
            .json({ error: "Yazdırma sırasında hata oluştu." });
        }

        res.json({ success: true, message: "Yazdırma başarılı." });
      }
    );
  });
});

app.get("/api/checkAdmin", (req, res) => {
  const clientIP = req.headers.origin || req.headers.referer || req.ip; // istemci IP'sini al

  if (!ALLOWED_ORIGINS.includes(clientIP)) {
    return res.status(403).json({ message: "Erişim reddedildi." });
  }
  const username = req.session?.user?.username;

  if (!username) {
    return res.status(401).json({ message: "Kullanıcı oturumu yok!" });
  }

  const query = `SELECT role FROM adminUsers WHERE username = ?`;

  db.query(query, [username], (err, results) => {
    if (err) {
      console.error("SQL hatası:", err.message);
      return res.status(500).json({ message: "Sunucu hatası" });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: "Kullanıcı bulunamadı." });
    }

    const userRole = results[0].role;

    res.json({
      username,
      isAuthorized:
        userRole === "admin" ||
        userRole === "personel" ||
        userRole === "monitor",
      role: userRole,
    });
  });
});

app.post("/api/logout", (req, res) => {
  const clientIP = req.headers.origin || req.headers.referer || req.ip; // istemci IP'sini al

  if (!ALLOWED_ORIGINS.includes(clientIP)) {
    return res.status(403).json({ message: "Erişim reddedildi." });
  }
  req.session.destroy((err) => {
    if (err) {
      console.error("Oturum sonlandırma hatası:", err);
      return res.status(500).json({ message: "Çıkış işlemi başarısız oldu." });
    }
    res.clearCookie("connect.sid"); // Çerezi temizle
    res.status(200).json({ message: "Çıkış başarılı" });
  });
});

app.post("/api/login", async (req, res) => {
  const clientIP = req.headers.origin || req.headers.referer || req.ip; // istemci IP'sini al

  if (!ALLOWED_ORIGINS.includes(clientIP)) {
    return res.status(403).json({ message: "Erişim reddedildi." });
  }
  const { username, password } = req.body;

  if (!username || !password) {
    return res
      .status(400)
      .json({ message: "Kullanıcı adı ve şifre gereklidir." });
  }

  try {
    const userQuery = "SELECT * FROM users WHERE username = ?";
    const userResults = await dbQuery(userQuery, [username]);

    if (!userResults || userResults.length === 0) {
      return res.status(401).json({ message: "Geçersiz kullanıcı adı." });
    }

    const user = userResults[0];
    const hashedPassword = user.password;

    if (!hashedPassword) {
      console.error("Kullanıcının hashlenmiş şifresi bulunamadı.");
      return res.status(500).json({ message: "Kullanıcı şifresi eksik." });
    }

    const isPasswordValid = await bcrypt.compare(password, hashedPassword);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Geçersiz şifre." });
    }

    req.session.user = { username: user.username, role: user.role };

    if (user.role === "admin") {
      return res.status(200).json({
        message: "Başarıyla giriş yapıldı!",
        user: { username: user.username, role: user.role },
        redirectTo: "/",
        permissions: "admin",
      });
    }

    const tableStatusQuery =
      "SELECT * FROM ETSTSR.tablestatus WHERE username = ?";
    const tableStatusResults = await dbQuery(tableStatusQuery, [username]);

    return res.status(200).json({
      message: "Başarıyla giriş yapıldı!",
      user: { username: user.username, role: user.role },
      redirectTo: "/show-user-status",
      permissions: tableStatusResults[0] || {},
    });
  } catch (error) {
    console.error("Giriş işlemi sırasında hata:", error);
    return res.status(500).json({ message: "Sunucu hatası." });
  }
});

app.get("/api/check-product-access/:fishNo", (req, res) => {
  const clientIP = req.headers.origin || req.headers.referer || req.ip; // istemci IP'sini al

  if (!ALLOWED_ORIGINS.includes(clientIP)) {
    return res.status(403).json({ message: "Erişim reddedildi." });
  }
  const { fishNo } = req.params;
  const username = req.session.user?.username;

  if (!username) {
    return res
      .status(401)
      .json({ isAuthorized: false, message: "Oturum açılmamış." });
  }

  const query = `SELECT * FROM ETSTSR.tablestatus WHERE username = ? AND ProductInfoPage = 1`;
  db.query(query, [username], (err, results) => {
    if (err) {
      console.error("Veritabanı hatası:", err);
      return res
        .status(500)
        .json({ isAuthorized: false, message: "Yetki bilgisi alınamadı." });
    }

    if (results.length > 0) {
      res.json({ isAuthorized: true });
    } else {
      res.json({ isAuthorized: false });
    }
  });
});

app.post("/api/check-page-access", (req, res) => {
  const clientIP = req.headers.origin || req.headers.referer || req.ip; // istemci IP'sini al

  if (!ALLOWED_ORIGINS.includes(clientIP)) {
    return res.status(403).json({ message: "Erişim reddedildi." });
  }
  const { username, page } = req.body;

  if (!username || !page) {
    return res
      .status(400)
      .json({ message: "Kullanıcı adı ve sayfa adı gereklidir!" });
  }

  // Kullanıcının admin olup olmadığını kontrol et
  const checkUserRoleQuery = `SELECT role FROM users WHERE username = ?`;

  db.query(checkUserRoleQuery, [username], (err, roleResult) => {
    if (err) {
      console.error("Veritabanı hatası:", err);
      return res.status(500).json({ message: "Kullanıcı rolü alınamadı." });
    }

    if (roleResult.length === 0) {
      return res.status(404).json({ message: "Kullanıcı bulunamadı." });
    }

    const userRole = roleResult[0].role;

    // Eğer kullanıcı adminse, erişime izin ver
    if (userRole === "admin") {
      return res.json({ message: "Erişim onaylandı." });
    }

    // Admin değilse, yetkiyi kontrol et
    const query = `SELECT ?? FROM ETSTSR.tablestatus WHERE username = ?`;

    db.query(query, [page, username], (err, results) => {
      if (err) {
        console.error("Veritabanı hatası:", err);
        return res.status(500).json({ message: "Yetki bilgileri alınamadı." });
      }

      if (results.length === 0 || results[0][page] !== 1) {
        return res.status(403).json({ message: "Erişim reddedildi." });
      }

      res.json({ message: "Erişim onaylandı." });
    });
  });
});

app.get("/api/get-user-permissions/:username", (req, res) => {
  const { username } = req.params;

  // Veritabanından tablestatus tablosundaki satırı çek
  const query = "SELECT * FROM tablestatus WHERE username = ? LIMIT 1";
  db.query(query, [username], (err, results) => {
    if (err) {
      console.error("Yetki bilgisi getirme hatası:", err);
      return res.status(500).json({
        error: "Veritabanı hatası",
        details: err.message,
      });
    }

    if (results.length === 0) {
      // Bu kullanıcı için tablo kaydı yoksa 404 dönebilirsin
      return res
        .status(404)
        .json({ message: "Kullanıcının tablestatus bilgisi bulunamadı." });
    }

    // Tablestatus satırını döndür
    // (örneğin {id:5, username:'ahmet', HomePage:1, AddProdPage:0, ...} gibi)
    res.json(results[0]);
  });
});

app.get("/api/get-session-user", (req, res) => {
  const clientIP = req.headers.origin || req.headers.referer || req.ip; // istemci IP'sini al

  if (!ALLOWED_ORIGINS.includes(clientIP)) {
    return res.status(403).json({ message: "Erişim reddedildi." });
  }
  if (req.session.user) {
    res.json({ username: req.session.user.username });
  } else {
    res.status(401).json({ message: "Oturum bulunamadı." });
  }
});

app.get("/api/get-user-records/:username", (req, res) => {
  const clientIP = req.headers.origin || req.headers.referer || req.ip; // istemci IP'sini al

  if (!ALLOWED_ORIGINS.includes(clientIP)) {
    return res.status(403).json({ message: "Erişim reddedildi." });
  }
  const { username } = req.params;

  // Kullanıcının görebileceği sütunları getir
  const statusQuery = "SELECT * FROM ETSTSR.tablestatus WHERE username = ?";
  db.query(statusQuery, [username], (err, statusResults) => {
    if (err) {
      console.error("Yetki kontrolü sırasında hata:", err.message);
      return res.status(500).json({ message: "Yetki kontrolü hatası." });
    }

    if (statusResults.length === 0) {
      return res.status(403).json({ message: "Yetkisiz erişim!" });
    }

    const userPermissions = statusResults[0];

    // **Sadece 1 olan sütunları al, ancak sayfa yetkilendirmelerini filtrele**
    const pageColumns = [
      "AddCustomerPage",
      "DeliveredProductsPage",
      "HomePage",
      "ProductInfoPage",
      "RecordFormPage",
      "ShowCostumerRecordsPage",
      "ShowUserInfoPage",
      "ChangeSettingsPage",
      "AddCustomer",
      "AddProdPage",
      "AddUserPage",
      // "ShowUserStatusPage",
      "EditUserPage",
      "ProdInfoPage",
    ];

    // **Yetkili olan ama sayfa olmayan sütunları seç**
    const allowedColumns = Object.keys(userPermissions).filter(
      (col) =>
        userPermissions[col] === 1 &&
        col !== "id" &&
        col !== "username" &&
        !pageColumns.includes(col)
    );

    if (allowedColumns.length === 0) {
      return res
        .status(403)
        .json({ message: "Bu kullanıcıya veri gösterilmiyor." });
    }

    const selectedColumns = allowedColumns.join(", "); // SQL için sütun listesi

    // Yetkili sütunları `records` tablosundan çek
    const recordsQuery = `SELECT ${selectedColumns} FROM records`;
    db.query(recordsQuery, (err, recordsResults) => {
      if (err) {
        console.error("Veri çekme hatası:", err.message);
        return res.status(500).json({ message: "Veri çekme hatası." });
      }

      res.status(200).json(recordsResults);
    });
  });
});

app.post("/api/add-user", async (req, res) => {
  const clientIP = req.headers.origin || req.headers.referer || req.ip; // istemci IP'sini al

  if (!ALLOWED_ORIGINS.includes(clientIP)) {
    return res.status(403).json({ message: "Erişim reddedildi." });
  }
  const { username, password, email, role } = req.body;

  if (!username || !password || !email || !role) {
    return res
      .status(400)
      .json({ success: false, message: "Tüm alanlar zorunludur." });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    // İlk query için
    const query = `INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)`;
    db.query(query, [username, hashedPassword, email, role], (err, results) => {
      if (err) {
        console.error("SQL hatası:", err.message);
        return res
          .status(500)
          .json({ success: false, message: "Sunucu hatası." });
      }

      // İkinci query'yi burada tetikliyorsanız
      const query2 = `INSERT INTO adminUsers (username, password, email, role) VALUES (?, ?, ?, ?)`;
      db.query(
        query2,
        [username, hashedPassword, email, role],
        (err, results) => {
          if (err) {
            console.error("SQL hatası:", err.message);
            return res
              .status(500)
              .json({ success: false, message: "Sunucu hatası." });
          }

          // Yanıtı bir kez gönderin
          return res
            .status(200)
            .json({ success: true, message: "Kullanıcı başarıyla eklendi." });
        }
      );
    });
  } catch (error) {
    console.error("Hata:", error.message);
    return res
      .status(500)
      .json({ success: false, message: "Bir hata oluştu." });
  }
});

app.put("/api/update-user/:id", async (req, res) => {
  const clientIP = req.headers.origin || req.headers.referer || req.ip; // istemci IP'sini al

  if (!ALLOWED_ORIGINS.includes(clientIP)) {
    return res.status(403).json({ message: "Erişim reddedildi." });
  }
  const userId = req.params.id;
  const { username, email, role, password } = req.body;

  try {
    let hashedPassword = null;

    // Şifre sağlanmışsa hashle
    if (password) {
      const saltRounds = 10;
      hashedPassword = await bcrypt.hash(password, saltRounds);
    }

    // İlk tabloyu güncelle
    const query1 = `
      UPDATE users 
      SET username = ?, email = ?, role = ?, password = COALESCE(?, password) 
      WHERE id = ?`;
    const params1 = [username, email, role, hashedPassword, userId];

    db.query(query1, params1, (err, results1) => {
      if (err) {
        console.error("SQL Hatası (users tablosu):", err.message);
        return res.status(500).json({ message: "Kullanıcı güncellenemedi!" });
      }

      if (results1.affectedRows === 0) {
        return res.status(404).json({ message: "Kullanıcı bulunamadı!" });
      }

      // İkinci tabloyu güncelle
      const query2 = `
        UPDATE adminUsers 
        SET username = ?, email = ?, role = ?, password = COALESCE(?, password) 
        WHERE id = ?`;
      const params2 = [username, email, role, hashedPassword, userId];

      db.query(query2, params2, (err, results2) => {
        if (err) {
          console.error("SQL Hatası (adminUsers tablosu):", err.message);
          return res.status(500).json({
            message: "Kullanıcı güncellenemedi (adminUsers tablosu)!",
          });
        }

        if (results2.affectedRows === 0) {
          return res
            .status(404)
            .json({ message: "Admin kullanıcı bulunamadı!" });
        }

        // Tüm işlemler başarıyla tamamlandıysa yanıt gönder
        res.json({
          message: "Kullanıcı her iki tabloda başarıyla güncellendi!",
        });
      });
    });
  } catch (err) {
    console.error("Şifre hashleme hatası:", err.message);
    res.status(500).json({ message: "Sunucu hatası!" });
  }
});

app.delete("/api/delete-user/:id", async (req, res) => {
  const clientIP = req.headers.origin || req.headers.referer || req.ip; // istemci IP'sini al

  if (!ALLOWED_ORIGINS.includes(clientIP)) {
    return res.status(403).json({ message: "Erişim reddedildi." });
  }
  const { id } = req.params;

  try {
    // İlk sorgu: 'users' tablosundan sil
    const deleteFromUsers = new Promise((resolve, reject) => {
      db.query("DELETE FROM users WHERE id = ?", [id], (err, result) => {
        if (err) return reject(err);
        resolve(result);
      });
    });

    // İkinci sorgu: 'adminUsers' tablosundan sil
    const deleteFromAdminUsers = new Promise((resolve, reject) => {
      db.query("DELETE FROM adminUsers WHERE id = ?", [id], (err, result) => {
        if (err) return reject(err);
        resolve(result);
      });
    });

    // Her iki işlemin tamamlanmasını bekle
    await Promise.all([deleteFromUsers, deleteFromAdminUsers]);

    res
      .status(200)
      .send({ message: "Kullanıcı her iki tablodan başarıyla silindi!" });
  } catch (error) {
    console.error("Silme hatası:", error);
    res.status(500).send({ error: "Silme işlemi başarısız oldu!" });
  }
});

app.get("/api/get-users-data", (req, res) => {
  const clientIP = req.headers.origin || req.headers.referer || req.ip; // istemci IP'sini al

  if (!ALLOWED_ORIGINS.includes(clientIP)) {
    return res.status(403).json({ message: "Erişim reddedildi." });
  }
  const query = "SELECT id, username, email, role, created_at FROM users";

  db.query(query, (err, results) => {
    if (err) {
      console.error("SQL Hatası:", err.message);
      return res.status(500).json({ message: "Kullanıcılar alınamadı!" });
    }

    res.json(results);
  });
});

app.get("/api/get-user/:id", (req, res) => {
  const clientIP = req.headers.origin || req.headers.referer || req.ip; // istemci IP'sini al

  if (!ALLOWED_ORIGINS.includes(clientIP)) {
    return res.status(403).json({ message: "Erişim reddedildi." });
  }
  const userId = req.params.id;
  const query =
    "SELECT id, username, email, role, created_at FROM users WHERE id = ?";

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error("SQL Hatası:", err.message);
      return res.status(500).json({ message: "Kullanıcı alınamadı!" });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: "Kullanıcı bulunamadı!" });
    }

    res.json(results[0]);
  });
});

app.post("/api/update-settings-for-user/:id", (req, res) => {
  const clientIP = req.headers.origin || req.headers.referer || req.ip; // istemci IP'sini al

  if (!ALLOWED_ORIGINS.includes(clientIP)) {
    return res.status(403).json({ message: "Erişim reddedildi." });
  }
  const userId = req.params.id;
  const { allowedColumns } = req.body;

  if (!allowedColumns || !Array.isArray(allowedColumns)) {
    return res.status(400).json({ message: "Geçersiz veri gönderildi." });
  }

  const columnsString = allowedColumns.join(",");

  const query = `
    INSERT INTO user_settings (user_id, allowed_columns)
    VALUES (?, ?)
    ON DUPLICATE KEY UPDATE allowed_columns = VALUES(allowed_columns)`;

  db.query(query, [userId, columnsString], (err) => {
    if (err) {
      console.error("SQL Hatası:", err.message);
      return res.status(500).json({ message: "Ayarlar güncellenemedi!" });
    }

    res.json({ message: "Ayarlar başarıyla güncellendi!" });
  });
});

// server.js (veya ilgili controller dosyası)

// user_settings tablosundan, kullanıcıya ait kayıtları döndüren endpoint
app.get("/api/get-user-settings/:username", (req, res) => {
  const { username } = req.params;
  // user_settings tablosunda username alanı varsa bu şekilde sorgula.
  // Sende "user_id" da olabilir. O zaman önce user'ı bulup, user.id ile arama yaparsın.
  const query = `
    SELECT * FROM user_settings
    WHERE username = ?
    LIMIT 1
  `;
  db.query(query, [username], (err, results) => {
    if (err) {
      console.error("user_settings sorgu hatası:", err);
      return res.status(500).json({ error: "Veritabanı hatası" });
    }

    if (results.length === 0) {
      return res.status(404).json({
        message: "Bu kullanıcı için user_settings tablosunda kayıt bulunamadı.",
      });
    }

    return res.json(results[0]);
  });
});

app.post("/api/change-user-settings", (req, res) => {
  const clientIP = req.headers.origin || req.headers.referer || req.ip; // istemci IP'sini al

  if (!ALLOWED_ORIGINS.includes(clientIP)) {
    return res.status(403).json({ message: "Erişim reddedildi." });
  }
  const { username, permissions } = req.body;

  if (!username || !permissions || Object.keys(permissions).length === 0) {
    return res
      .status(400)
      .json({ message: "Kullanıcı adı ve yetkiler boş olamaz!" });
  }

  const columnsNames = Object.keys(permissions);
  const columnsValues = Object.values(permissions);

  // Kullanıcı var mı kontrol et
  const checkQuery = `SELECT COUNT(*) AS count FROM ETSTSR.tablestatus WHERE username = ?`;

  db.query(checkQuery, [username], (err, result) => {
    if (err) {
      console.error("SQL Hatası:", err.message || err);
      return res.status(500).json({ message: "Veritabanı hatası oluştu." });
    }

    const userExists = result[0].count > 0;

    if (userExists) {
      // Kullanıcı varsa UPDATE yap
      const updateQuery = `
        UPDATE ETSTSR.tablestatus 
        SET ${columnsNames.map((col) => `${col} = ?`).join(", ")}
        WHERE username = ?
      `;

      db.query(
        updateQuery,
        [...columnsValues, username],
        (err, updateResult) => {
          if (err) {
            console.error("SQL Güncelleme Hatası:", err.message || err);
            return res
              .status(500)
              .json({ message: "Yetki güncellenirken hata oluştu." });
          }
          res.status(200).json({ message: "Yetkiler başarıyla güncellendi." });
        }
      );
    } else {
      // Kullanıcı yoksa INSERT yap
      const insertQuery = `
        INSERT INTO ETSTSR.tablestatus (username, ${columnsNames.join(", ")})
        VALUES (?, ${columnsNames.map(() => "?").join(", ")})
      `;

      db.query(
        insertQuery,
        [username, ...columnsValues],
        (err, insertResult) => {
          if (err) {
            console.error("SQL Ekleme Hatası:", err.message || err);
            return res
              .status(500)
              .json({ message: "Yetki eklenirken hata oluştu." });
          }
          res.status(200).json({ message: "Yetkiler başarıyla eklendi." });
        }
      );
    }
  });
});

app.get("/api/delivered-products", (req, res) => {
  const clientIP = req.headers.origin || req.headers.referer || req.ip; // istemci IP'sini al

  if (!ALLOWED_ORIGINS.includes(clientIP)) {
    return res.status(403).json({ message: "Erişim reddedildi." });
  }
  const query = "SELECT * FROM records WHERE Durum = 'Teslim Edildi'";
  db.query(query, (err, results) => {
    if (err) {
      console.error("Veritabanı hatası:", err.message);
      return res.status(500).json({ message: "Veritabanı hatası" });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: "Kayıt bulunamadı" });
    }

    // Tüm kayıtları döndürüyoruz
    res.json({ data: results });
  });
});

app.get("/api/getInfoProd/:fishNo", (req, res) => {
  const clientIP = req.headers.origin || req.headers.referer || req.ip; // istemci IP'sini al

  if (!ALLOWED_ORIGINS.includes(clientIP)) {
    return res.status(403).json({ message: "Erişim reddedildi." });
  }
  const fishNo = req.params.fishNo;

  const query = "SELECT * FROM records WHERE fishNo = ? LIMIT 1";
  db.query(query, [fishNo], (err, results) => {
    if (err) {
      console.error("Veritabanı hatası:", err.message);
      return res.status(500).json({ message: "Veritabanı hatası" });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: "Kayıt bulunamadı" });
    }

    res.json({ data: results[0] });
  });
});

app.get("/api/protected", authMiddleware, (req, res) => {
  const clientIP = req.headers.origin || req.headers.referer || req.ip; // istemci IP'sini al

  if (!ALLOWED_ORIGINS.includes(clientIP)) {
    return res.status(403).json({ message: "Erişim reddedildi." });
  }

  const username = req.session.user?.username;

  if (!username) {
    return res.status(401).json({ message: "Yetkilendirilmemiş erişim!" });
  }

  // Veritabanı kontrolü seçeneği
  const includeDB = req.query.includeDB === "true"; // ?includeDB=true parametresi kontrol ediliyor

  if (includeDB) {
    const query = "SELECT username, role FROM users WHERE username = ?";
    db.query(query, [username], (err, results) => {
      if (err) {
        console.error("Veritabanı hatası:", err.message);
        return res.status(500).json({ message: "Sunucu hatası" });
      }

      if (results.length === 0) {
        return res.status(404).json({ message: "Kullanıcı bulunamadı" });
      }

      const user = results[0];
      // Veritabanı bilgilerini döndür
      res.json({
        user: {
          username: user.username,
          role: user.role,
          isAdmin: user.role === "admin",
        },
        message: "Veritabanı kontrolü başarıyla tamamlandı.",
      });
    });
  } else {
    // Sadece oturum bilgilerini döndür
    res.json({
      message: "Yetkili erişim sağlandı.",
      user: req.session.user,
    });
  }
});

app.get("/api/records", authMiddleware, (req, res) => {
  const clientIP = req.headers.origin || req.headers.referer || req.ip; // istemci IP'sini al

  if (!ALLOWED_ORIGINS.includes(clientIP)) {
    return res.status(403).json({ message: "Erişim reddedildi." });
  }
  const { username, role } = req.user; // authMiddleware'den gelen kullanıcı bilgileri

  // Eğer kullanıcı 'monitor' rolündeyse sadece kayıtları görsün, düzenleme yapamasın
  if (role === "monitor") {
    const query = "SELECT * FROM records"; // Kayıtları görme yetkisi
    db.query(query, (err, results) => {
      if (err) {
        console.error("Database error (Monitor access):", err.message);
        return res.status(500).json({ message: "Server error." });
      }
      return res.json({ data: results });
    });
  } else if (role === "admin" || role === "personel") {
    const query = "SELECT * FROM records"; // Admin ve Personel düzenleme yetkisi de olabilir
    db.query(query, (err, results) => {
      if (err) {
        console.error(
          "Database error (Admin or Personel access):",
          err.message
        );
        return res.status(500).json({ message: "Server error." });
      }
      return res.json({ data: results });
    });
  } else {
    return res.status(403).json({ message: "Unauthorized access!" }); // Diğer rollere kısıtlama
  }
});

app.get("/api/record/:fishNo", (req, res) => {
  const { fishNo } = req.params;
  const clientIP = req.headers.origin || req.headers.referer || req.ip; // İstemci IP'sini al

  if (!fishNo) {
    return res.status(400).json({ message: "Fiş numarası gerekli." });
  }

  const query = "SELECT * FROM records WHERE fishNo = ?";
  db.query(query, [fishNo], (err, results) => {
    if (err) {
      console.error("Veritabanı hatası:", err.message);
      return res.status(500).json({ message: "Sunucu hatası." });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: "Kayıt bulunamadı." });
    }

    // ** eğer istek yetkili istemciden gelmiyorsa mesaj döndür **
    if (clientIP !== "http://192.168.0.201:80") {
      return res
        .status(403)
        .json({ message: "Bu verilere erişim izniniz yok." });
    }

    // yetkili istemciye tam veriyi gönder
    res.json(results[0]);
  });
});

app.get("/api/get-all-fishNos", (req, res) => {
  const clientIP = req.headers.origin || req.headers.referer || req.ip; // istemci IP'sini al

  if (clientIP !== "http://192.168.0.201:80") {
    return res.status(403).json({ message: "Bu verilere erişim izniniz yok." });
  }

  const query = "SELECT fishNo FROM records"; // tüm geçerli `fishNo` değerlerini al

  db.query(query, (err, results) => {
    if (err) {
      console.error("Veritabanı hatası:", err);
      return res.status(500).json({ message: "fishNo verileri alınamadı." });
    }

    const fishNos = results.map((row) => row.fishNo); // fishNo değerlerini bir diziye çevir
    res.json(fishNos);
  });
});

app.put("/api/record/:fishNo", (req, res) => {
  const clientIP = req.headers.origin || req.headers.referer || req.ip; // İstemci IP'sini al

  if (clientIP !== "http://192.168.0.201:80") {
    return res.status(403).json({ message: "Bu verilere erişim izniniz yok." });
  }
  const { fishNo } = req.params;
  const {
    AdSoyad,
    TelNo,
    SeriNo,
    TeslimAlan,
    Durum,
    Teknisyen,
    Urun,
    Marka,
    Model,
    GarantiDurumu,
    Ucret,
    Sorunlar,
    BirlikteAlinanlar,
    Aciklama,
    Yapilanlar,
    HazirlamaTarihi,
    TeslimEtmeTarihi,
  } = req.body;

  console.log("Gelen Veriler:", req.body); // Verilerin eksiksiz geldiğini kontrol et

  const sanitizeInput = (value) => (value === undefined ? null : value);

  const queryParams = [
    sanitizeInput(AdSoyad) || "",
    sanitizeInput(TelNo) || "",
    sanitizeInput(SeriNo) || "",
    sanitizeInput(TeslimAlan) || "",
    sanitizeInput(Durum) || "",
    sanitizeInput(Teknisyen) || "",
    sanitizeInput(Urun) || "",
    sanitizeInput(Marka) || "",
    sanitizeInput(Model) || "",
    sanitizeInput(GarantiDurumu) || "",
    parseFloat(Ucret),
    // Ucret,
    sanitizeInput(BirlikteAlinanlar) || "",
    sanitizeInput(Sorunlar) || "",
    sanitizeInput(Aciklama) || "",
    sanitizeInput(Yapilanlar) || "",
    HazirlamaTarihi ? formatDateForMySQL(HazirlamaTarihi) : null,
    TeslimEtmeTarihi ? formatDateForMySQL(TeslimEtmeTarihi) : null,
    fishNo,
  ];

  const query = `
    UPDATE records 
    SET AdSoyad = ?, TelNo = ?, SeriNo = ?, TeslimAlan = ?, Durum = ?, 
        Teknisyen = ?, Urun = ?, Marka = ?, Model = ?, GarantiDurumu = ?, Ucret = ?, BirlikteAlinanlar = ? ,Sorunlar = ?, Aciklama = ?, Yapilanlar = ?,
        HazirlamaTarihi = ?, TeslimEtmeTarihi = ?
    WHERE fishNo = ?
  `;

  console.log("Güncellenen Değerler:", queryParams);

  db.query(query, queryParams, (err, results) => {
    if (err) {
      console.error("Veritabanı güncelleme hatası:", err.message);
      return res
        .status(500)
        .json({ error: "Güncelleme sırasında hata oluştu." });
    }

    if (results.affectedRows > 0) {
      res.status(200).json({ message: "Kayıt başarıyla güncellendi!" });
    } else {
      res.status(404).json({ message: "Belirtilen kayıt bulunamadı." });
    }
  });
});

app.get("/api/export-records", (req, res) => {
  const clientIP = req.headers.origin || req.headers.referer || req.ip; // istemci IP'sini al

  if (!ALLOWED_ORIGINS.includes(clientIP)) {
    return res.status(403).json({ message: "Erişim reddedildi." });
  }
  const query = `
    SELECT fishNo, AdSoyad, DATE_FORMAT(TeslimAlmaTarihi, '%Y-%m-%d %H:%i:%s') AS TeslimAlmaTarihi, 
           TelNo, Urun, Marka, Model, SeriNo, GarantiDurumu, TeslimAlan, Teknisyen, 
           Ucret, Sorunlar, DATE_FORMAT(HazirlamaTarihi, '%Y-%m-%d %H:%i:%s') AS HazirlamaTarihi, 
           DATE_FORMAT(TeslimEtmeTarihi, '%Y-%m-%d %H:%i:%s') AS TeslimEtmeTarihi, Durum 
    FROM records
  `;

  db.query(query, (err, results) => {
    if (err) {
      console.error("Veritabanı hatası:", err.message);
      return res
        .status(500)
        .json({ error: "Veritabanından veriler alınırken hata oluştu." });
    }

    res.status(200).json(results);
  });
});

app.post("/api/record", (req, res) => {
  const clientIP = req.headers.origin || req.headers.referer || req.ip; // istemci IP'sini al

  if (!ALLOWED_ORIGINS.includes(clientIP)) {
    return res.status(403).json({ message: "Erişim reddedildi." });
  }
  const { AdSoyad } = req.body;

  if (!AdSoyad) {
    return res.status(400).json({ message: "Adı Soyadı alanı gereklidir." });
  }

  const query = "INSERT INTO records (AdSoyad) VALUES (?)";
  db.query(query, [AdSoyad], (err, results) => {
    if (err) {
      console.error("Veritabanı hatası:", err);
      return res.status(500).json({ message: "Sunucu hatası." });
    }

    res.status(201).json({
      message: "Kayıt başarıyla eklendi!",
      recordId: results.insertId,
    });
  });
});

const generateCustomID = () => {
  const randomDigits = () => Math.floor(100 + Math.random() * 900); // 100-999 arasında rastgele sayı üret
  return `${randomDigits()}-${randomDigits()}-${randomDigits()}`;
};

app.post("/api/addpro", (req, res) => {
  const clientIP = req.headers.origin || req.headers.referer || req.ip;

  if (!ALLOWED_ORIGINS.includes(clientIP)) {
    return res.status(403).json({ message: "Erişim reddedildi." });
  }

  const {
    AdSoyad,
    TelNo,
    TeslimAlan,
    Teknisyen,
    SeriNo,
    Urun,
    Marka,
    Model,
    GarantiDurumu,
    BirlikteAlinanlar,
    Sorunlar,
    Aciklama,
    kdv,
  } = req.body;

  if (
    !AdSoyad ||
    !TelNo ||
    !TeslimAlan ||
    !Teknisyen ||
    !SeriNo ||
    !Urun ||
    !Marka ||
    !Model ||
    !GarantiDurumu ||
    !Sorunlar
  ) {
    console.error("Eksik Alanlar:", req.body);
    return res
      .status(400)
      .json({ message: "Tüm alanların doldurulması zorunludur!" });
  }

  const kdvOrani = kdv ? parseFloat(kdv) : 20;

  // Teknisyen alanını artık parametreden alıyoruz, bu yüzden 'Ibrahim Bey' sabiti kaldırıldı.
  const insertRecordQuery = `\
    INSERT INTO ETSTSR.records\n    (AdSoyad, TeslimAlmaTarihi, TelNo, TeslimAlan, Teknisyen, SeriNo, Urun, Marka, Model, GarantiDurumu, BirlikteAlinanlar, Sorunlar, Aciklama, Ucret, HazirlamaTarihi, TeslimEtmeTarihi, Durum, kdv)\n    VALUES (?, NOW(), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, 'Bekliyor', ?);\
  `;

  db.query(
    insertRecordQuery,
    [
      AdSoyad,
      TelNo,
      TeslimAlan,
      Teknisyen,
      SeriNo,
      Urun,
      Marka,
      Model,
      GarantiDurumu,
      BirlikteAlinanlar,
      Sorunlar,
      Aciklama,
      kdvOrani,
    ],
    (err, result) => {
      if (err) {
        console.error("SQL Hatası (record ekleme):", err.message);
        return res
          .status(500)
          .json({ message: "Bir hata oluştu.", error: err.message });
      }

      // **Eklendikten sonra ilgili fishNo değerini al**
      db.query(
        "SELECT fishNo FROM ETSTSR.records WHERE AdSoyad = ? ORDER BY fishNo DESC LIMIT 1;",
        [AdSoyad],
        (err, rows) => {
          if (err) {
            console.error("SQL Hatası (fishNo alma):", err.message);
            return res
              .status(500)
              .json({ message: "fishNo alınamadı.", error: err.message });
          }

          if (!rows || rows.length === 0) {
            return res
              .status(500)
              .json({ message: "fishNo değeri bulunamadı!" });
          }

          const fishNoID = rows[0].fishNo; // fishNo değerini al
          const customID = generateCustomID(); // Yeni formatta ID oluştur

          // **costumerData'ya ekle**
          const costumerQuery = `\
            INSERT INTO ETSTSR.costumerData (id, AdSoyad, fishNoID)\n            VALUES (?, ?, ?)\n            ON DUPLICATE KEY UPDATE fishNoID = VALUES(fishNoID);\
          `;

          db.query(
            costumerQuery,
            [customID, AdSoyad, fishNoID],
            (err, result) => {
              if (err) {
                console.error("SQL Hatası (costumerData ekleme):", err.message);
                return res
                  .status(500)
                  .json({ message: "Bir hata oluştu.", error: err.message });
              }

              res.status(201).json({
                message: "Ürün başarıyla eklendi!",
                recordId: result.insertId,
                fishNoID: fishNoID,
                customID: customID, // Yeni oluşturulan ID'yi döndür
              });
            }
          );
        }
      );
    }
  );
});

app.delete("/api/deleteProduct/:fishNo", async (req, res) => {
  const clientIP = req.headers.origin || req.headers.referer || req.ip; // istemci IP'sini al

  if (!ALLOWED_ORIGINS.includes(clientIP)) {
    return res.status(403).json({ message: "Erişim reddedildi." });
  }

  const { fishNo } = req.params;

  try {
    // Ürünü veritabanından silmek için SQL sorgusunu çalıştırıyoruz
    const query = "DELETE FROM records WHERE fishNo = ?";

    // Veritabanı sorgusunu çalıştır
    db.query(query, [fishNo], (err, result) => {
      if (err) {
        console.error("Veritabanı hatası:", err.message);
        return res.status(500).json({ message: "Sunucu hatası" });
      }

      // Silme işlemi başarılıysa
      if (result.affectedRows === 0) {
        return res.status(404).json({ message: "Ürün bulunamadı" });
      }

      // Ürün başarıyla silindi
      res.status(200).json({ message: "Ürün başarıyla silindi" });
    });
  } catch (error) {
    console.error("Silme hatası:", error.message);
    res.status(500).json({ message: "Sunucu hatası" });
  }
});

app.get("/", (req, res) => {
  const clientIP = req.headers.origin || req.headers.referer || req.ip; // istemci IP'sini al

  if (!ALLOWED_ORIGINS.includes(clientIP)) {
    return res.status(403).json({ message: "Erişim reddedildi." });
  }
});

app.all(/^\/.*/, (req, res) => {
  const clientIP = req.headers.origin || req.headers.referer || req.ip;

  if (!ALLOWED_ORIGINS.includes(clientIP)) {
    return res.status(403).json({ message: "Erişim reddedildi." });
  }

  res.status(404).send("Sayfa bulunamadı.");
});

server.listen(PORT, () => {
  console.log(`http://192.168.0.201:${PORT}`);
});
