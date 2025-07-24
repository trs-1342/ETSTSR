CREATE DATABASE IF NOT EXISTS sp;
USE sp;

CREATE TABLE records (
  FishNo INT AUTO_INCREMENT PRIMARY KEY,
  AdSoyad VARCHAR(100),
  TelNo VARCHAR(50),
  TeslimAlan VARCHAR(100),
  Teknisyen VARCHAR(100),
  SeriNo VARCHAR(100),
  Urun VARCHAR(100),
  Marka VARCHAR(100),
  Model VARCHAR(100),
  GarantiDurumu VARCHAR(100),
  BirlikteAlinanlar TEXT,
  Sorunlar TEXT,
  Aciklama TEXT,
  Yapilanlar TEXT,
  TeslimAlmaTarihi DATETIME,
  HazirlamaTarihi DATETIME,
  TeslimEtmeTarihi DATETIME,
  Durum VARCHAR(50),
  Ucret DECIMAL(10,2),
  KDV DECIMAL(5,2)
);

CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(100) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  email VARCHAR(150),
  role VARCHAR(50) DEFAULT('personel'),
  createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE costumerData (
  id VARCHAR(20) PRIMARY KEY,
  AdSoyad VARCHAR(100),
  FishNoID INT,
  FOREIGN KEY (FishNoID) REFERENCES records(FishNo)
);

CREATE TABLE tablestatus (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(100) UNIQUE,
  HomePage TINYINT DEFAULT 0,
  AddCustomerPage TINYINT DEFAULT 0,
  DeliveredProductsPage TINYINT DEFAULT 0,
  ProductInfoPage TINYINT DEFAULT 0,
  RecordFormPage TINYINT DEFAULT 0,
  ShowCostumerRecordsPage TINYINT DEFAULT 0,
  ShowUserInfoPage TINYINT DEFAULT 0,
  ChangeSettingsPage TINYINT DEFAULT 0,
  AddCustomer TINYINT DEFAULT 0,
  AddProdPage TINYINT DEFAULT 0,
  AddUserPage TINYINT DEFAULT 0,
  EditUserPage TINYINT DEFAULT 0,
  ProdInfoPage TINYINT DEFAULT 0
);

SELECT * FROM sp.users;
SELECT * FROM sp.records;