import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import "bootstrap/dist/css/bootstrap.min.css";
import * as exceljs from "exceljs";
import { MdEditSquare } from "react-icons/md";
import "../css/HomePage.css";
import usePageAccess from "./usePageAccess";
import ToolsPanel from "./ToolsPanel";

function formatTarihVeSaat(tarih) {
  if (!tarih) return "Bilinmiyor";

  const d = new Date(tarih);
  if (isNaN(d.getTime())) return "Geçersiz Tarih";

  const year = d.getFullYear();
  const month = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  const hours = String(d.getHours()).padStart(2, "0");
  const minutes = String(d.getMinutes()).padStart(2, "0");

  return `${day}/${month}/${year} ${hours}:${minutes}`;
}

export default function HomePage() {
  const navigate = useNavigate();
  const [kayitlar, setKayitlar] = useState([]);
  const [filtre, setFiltre] = useState("Hepsi");
  const [garantiFiltre, setGarantiFiltre] = useState("Hepsi");
  const [filtreTarihi, setFiltreTarihi] = useState("");
  const [acikDetaylar, setAcikDetaylar] = useState({});
  const [sortConfig, setSortConfig] = useState({ key: null, direction: "asc" });
  const [isPanelOpen, setIsPanelOpen] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");
  const [filteredResults, setFilteredResults] = useState([]);
  const [isAuthorized, setIsAuthorized] = useState(false);
  const [userRole, setUserRole] = useState(""); // Kullanıcı rolü için state
  const { hasAccess, loading } = usePageAccess("HomePage");
  const [role, setRole] = useState("");
  const [allowedColumns, setAllowedColumns] = useState([]);
  const [userId, setUserId] = useState(null); // Initialize userId state
  const [userData, setUserData] = useState(null);
  const [sessionLost, setSessionLost] = useState(false); // Alert için state

  if (!userRole) {
    <></>;
  }

  useEffect(() => {
    // Hem çerez hem de localStorage kontrolü
    const userInLocalStorage = localStorage.getItem("user");
    const cookies = document.cookie;

    if (!userInLocalStorage && !cookies) {
      navigate("/login");
    }
  }, [navigate]);

  const [serverRestarted, setServerRestarted] = useState(false);

  // 1) Oturum ve yetki bilgisini kontrol et
  useEffect(() => {
    const checkSession = async () => {
      try {
        const resp = await fetch("http://127.0.0.1:2431/api/checkAdmin", {
          method: "GET",
          credentials: "include",
        });
        if (resp.status === 401 || resp.status === 403) {
          setServerRestarted(true);
          return;
        }
        if (!resp.ok) {
          setServerRestarted(true);
          return;
        }
        const data = await resp.json();
        setIsAuthorized(data.isAuthorized);
        setUserRole(data.role);
      } catch (error) {
        console.error("Oturum kontrol hatası:", error);
        setServerRestarted(true);
      }
    };
    checkSession();
  }, []);

  // 2) Kayıtları çek
  useEffect(() => {
    if (!isAuthorized) return;
    const fetchRecords = async () => {
      try {
        const response = await fetch("http://127.0.0.1:2431/api/records", {
          method: "GET",
          credentials: "include",
        });
        if (response.status === 401 || response.status === 403) {
          setServerRestarted(true);
          return;
        }
        if (!response.ok) {
          throw new Error("Yetkisiz erişim!");
        }
        const data = await response.json();
        // TeslimAlmaTarihi'ne göre sıralıyoruz
        const sortedData = [...data.data].sort((a, b) => {
          if (!a.TeslimAlmaTarihi) return 1;
          if (!b.TeslimAlmaTarihi) return -1;
          const dateA = parseDateString(a.TeslimAlmaTarihi);
          const dateB = parseDateString(b.TeslimAlmaTarihi);
          if (!dateA) return 1;
          if (!dateB) return -1;
          return dateB - dateA;
        });
        setKayitlar(sortedData);
      } catch (error) {
        console.error("Kayıtları getirirken hata:", error.message);
      }
    };
    fetchRecords();
  }, [isAuthorized]);

  const handleSearch = (e) => {
    const term = e.target.value.toLowerCase();
    setSearchTerm(term);

    const results = kayitlar.filter(
      (kayit) =>
        kayit.AdSoyad?.toLowerCase().includes(term) ||
        kayit.Urun?.toLowerCase().includes(term) ||
        kayit.Marka?.toLowerCase().includes(term) ||
        kayit.Model?.toLowerCase().includes(term) ||
        kayit.GarantiDurumu?.toLowerCase().includes(term) ||
        kayit.Sorunlar?.toLowerCase().includes(term) ||
        kayit.Yapilanlar?.toLowerCase().includes(term) ||
        kayit.BirlikteAlinanlar?.toLowerCase().includes(term) ||
        kayit.Aciklama?.toLowerCase().includes(term) ||
        kayit.TelNo?.toLowerCase().includes(term) ||
        kayit.SeriNo?.toLowerCase().includes(term) ||
        kayit.Teknisyen?.toLowerCase().includes(term) ||
        kayit.Durum?.toLowerCase().includes(term) ||
        kayit.TeslimAlmaTarihi?.toLowerCase().includes(term) ||
        kayit.TeslimEtmeTarihi?.toLowerCase().includes(term) ||
        kayit.HazirlamaTarihi?.toLowerCase().includes(term) ||
        kayit.TeslimAlan?.toLowerCase().includes(term)
    );

    setFilteredResults(results);
  };

  const filtrelenmisKayitlar = (kayitlar || []).filter((kayit) => {
    const durumUygun = filtre === "Hepsi" || kayit.Durum === filtre;
    const garantiUygun =
      garantiFiltre === "Hepsi" || kayit.GarantiDurumu === garantiFiltre;
    const tarihUygun =
      !filtreTarihi ||
      (kayit.TeslimAlmaTarihi &&
        kayit.TeslimAlmaTarihi.startsWith(filtreTarihi));

    return durumUygun && garantiUygun && tarihUygun;
  });

  const toggleDetay = (index) => {
    setAcikDetaylar((prevState) => ({
      ...prevState,
      [index]: !prevState[index],
    }));
  };

  function parseDateString(dateString) {
    const [datePart, timePart] = dateString.split(" ");
    if (!datePart || !timePart) return null;

    const [day, month, year] = datePart.split("/").map(Number);
    const [hour, minute] = timePart.split(":").map(Number);

    return new Date(year, month - 1, day, hour, minute);
  }

  useEffect(() => {
    setSortConfig({ key: "TeslimAlmaTarihi", direction: "desc" });

    // kayitlari yeniden duzenle
    const sorted = [...kayitlar].sort((a, b) => {
      if (!a.TeslimAlmaTarihi) return 1;
      if (!b.TeslimAlmaTarihi) return -1;

      const dateA = parseDateString(a.TeslimAlmaTarihi);
      const dateB = parseDateString(b.TeslimAlmaTarihi);
      if (!dateA) return 1;
      if (!dateB) return -1;

      return dateB - dateA;
    });
    setKayitlar(sorted);
  }, []);

  const sortData = (key) => {
    let direction = "asc";

    if (sortConfig.key !== key) {
      direction = "asc";
    } else {
      direction = sortConfig.direction === "asc" ? "desc" : "asc";
    }

    setSortConfig({ key, direction });

    const sortedData = [...kayitlar].sort((a, b) => {
      if (!a[key]) return 1;
      if (!b[key]) return -1;

      if (
        key === "TeslimAlmaTarihi" ||
        key === "HazirlamaTarihi" ||
        key === "TeslimEtmeTarihi"
      ) {
        const dateA = parseDateString(a[key]);
        const dateB = parseDateString(b[key]);

        if (!dateA) return 1;
        if (!dateB) return -1;

        return direction === "asc" ? dateA - dateB : dateB - dateA;
      }

      if (typeof a[key] === "string" && typeof b[key] === "string") {
        return direction === "asc"
          ? a[key].localeCompare(b[key])
          : b[key].localeCompare(a[key]);
      }

      return direction === "asc" ? a[key] - b[key] : b[key] - a[key];
    });

    setKayitlar(sortedData);
  };

  const exportAllRecordsToExcel = () => {
    const filteredKayitlar = kayitlar.filter(
      (row) => row.Durum !== "Teslim Edildi"
    );

    const header = [
      "Fis No",
      "Ad Soyad",
      "Teslim Alma Tarihi",
      "TelNo",
      "Ürün",
      "Marka",
      "Model",
      "Seri No",
      "Garanti Durumu",
      "Teslim Alan",
      "Teknisyen",
      "Ücret",
      "Sorun",
      "Aciklama",
      "Yapilanlar",
      "Hazırlama Tarihi",
      "Teslim Etme Tarihi",
      "Durum",
    ];

    const rows = filteredKayitlar.map((row) => [
      row.FishNo,
      row.AdSoyad,
      row.TeslimAlmaTarihi,
      row.TelNo,
      row.Urun,
      row.Marka,
      row.Model,
      row.SeriNo,
      row.GarantiDurumu,
      row.TeslimAlan,
      row.Teknisyen,
      row.Ucret,
      row.Sorunlar,
      row.Aciklama,
      row.Yapilanlar,
      row.HazirlamaTarihi,
      row.TeslimEtmeTarihi,
      row.Durum,
    ]);

    const ws = exceljs.utils.aoa_to_sheet([header, ...rows]);
    const wb = exceljs.utils.book_new();
    exceljs.utils.book_append_sheet(wb, ws, "Tüm Kayıtlar");
    exceljs.writeFile(wb, "tüm kayıtlar.exceljs");
  };

  const exportFilteredRecordsToExcel = () => {
    // Eğer hiçbir filtre seçilmediyse uyarı ver
    if (filtre === "Hepsi" && garantiFiltre === "Hepsi" && !filtreTarihi) {
      alert("Lütfen bir filtre seçiniz!");
      return;
    }

    // 'Teslim Edildi' durumunu hariç tutarak filtreleme
    const filteredKayitlar = kayitlar.filter(
      (row) => row.Durum !== "Teslim Edildi"
    );

    // Filtrelenmiş kayıtlara göre dışa aktarma işlemi
    let filteredRecords = filteredKayitlar;

    // Durum filtresi varsa uygula
    if (filtre !== "Hepsi") {
      filteredRecords = filteredRecords.filter((row) => row.Durum === filtre);
    }

    // Garanti filtresi varsa uygula
    if (garantiFiltre !== "Hepsi") {
      filteredRecords = filteredRecords.filter(
        (row) => row.GarantiDurumu === garantiFiltre
      );
    }

    // Tarih filtresi varsa uygula
    if (filtreTarihi) {
      const filteredDate = new Date(filtreTarihi); // filtre tarihini Date nesnesine çeviriyoruz
      filteredRecords = filteredRecords.filter((row) => {
        const rowDate = new Date(row.TeslimAlmaTarihi); // row.TeslimAlmaTarihi'ni Date nesnesine çeviriyoruz
        // Yalnızca yıl, ay ve gün karşılaştırması yapıyoruz
        return (
          rowDate.getFullYear() === filteredDate.getFullYear() &&
          rowDate.getMonth() === filteredDate.getMonth() &&
          rowDate.getDate() === filteredDate.getDate()
        );
      });
    }

    // Eğer hiçbir kayıt kalmadıysa, kullanıcıya uyarı ver
    if (filteredRecords.length === 0) {
      alert("Seçilen filtrelerle eşleşen veri bulunamadı.");
      return;
    }

    // Başlıkları ve satırları ayarlıyoruz
    let header = [];
    let rows = [];

    if (garantiFiltre === "Garantisiz") {
      header = [
        "Fis No",
        "Ad Soyad",
        "Garanti Durumu",
        "Ürün",
        "Marka",
        "Model",
        "Seri No",
      ];
      rows = filteredRecords.map((row) => [
        row.FishNo,
        row.AdSoyad,
        row.GarantiDurumu,
        row.Urun,
        row.Marka,
        row.Model,
        row.SeriNo,
      ]);
    } else {
      header = [
        "Fis No",
        "Ad Soyad",
        "Teslim Alma Tarihi",
        "TelNo",
        "Ürün",
        "Marka",
        "Model",
        "Seri No",
        "Garanti Durumu",
        "Teslim Alan",
        "Teknisyen",
        "Ücret",
        "Sorun",
        "Aciklama",
        "Yapilanlar",
        "Hazırlama Tarihi",
        "Teslim Etme Tarihi",
        "Durum",
      ];
      rows = filteredRecords.map((row) => [
        row.FishNo,
        row.AdSoyad,
        row.TeslimAlmaTarihi,
        row.TelNo,
        row.Urun,
        row.Marka,
        row.Model,
        row.SeriNo,
        row.GarantiDurumu,
        row.TeslimAlan,
        row.Teknisyen,
        row.Ucret,
        row.Sorun,
        row.Aciklama,
        row.Yapilanlar,
        row.HazırlamaTarihi,
        row.TeslimEtmeTarihi,
        row.Durum,
      ]);
    }

    // Excel dosyasını oluşturuyoruz
    const worksheet = exceljs.utils.aoa_to_sheet([header, ...rows]);
    const workbook = exceljs.utils.book_new();
    exceljs.utils.book_append_sheet(workbook, worksheet, "Kayıtlar");

    // Excel dosyasını indir
    exceljs.writeFile(workbook, "filterli kayıtlar.exceljs");
  };

  let selectedRecords = [];

  // Checkbox'ların durumunu değiştirdiğimizde çağrılacak fonksiyon
  const handleCheckboxChange = (record, event) => {
    if (event.target.checked) {
      // Checkbox seçildiyse kaydı diziye ekle
      selectedRecords.push(record);
    } else {
      // Checkbox seçilmediyse kaydı diziden çıkar
      selectedRecords = selectedRecords.filter(
        (item) => item.FishNo !== record.FishNo
      );
    }
  };

  // Seçilen kayıtları Excel'e aktarma fonksiyonu
  const exportSelectedRecordsToExcel = () => {
    if (selectedRecords.length === 0) {
      alert("Lütfen en az bir ürün seçin!");
      return;
    }

    // Başlıklar
    const header = [
      "Fis No",
      "Ad Soyad",
      "Teslim Alma Tarihi",
      "TelNo",
      "Ürün",
      "Marka",
      "Model",
      "Seri No",
      "Garanti Durumu",
      "Teslim Alan",
      "Teknisyen",
      "Ücret",
      "Sorun",
      "Aciklama",
      "Yapilanlar",
      "Hazırlama Tarihi",
      "Teslim Etme Tarihi",
      "Durum",
    ];

    // Satırlar (seçilen ürünler)
    const rows = selectedRecords.map((record) => [
      record.FishNo,
      record.AdSoyad,
      record.TeslimAlmaTarihi,
      record.TelNo,
      record.Urun,
      record.Marka,
      record.Model,
      record.SeriNo,
      record.GarantiDurumu,
      record.TeslimAlan,
      record.Teknisyen,
      record.Ucret,
      record.Sorunlar,
      record.Aciklama,
      record.Yapilanlar,
      record.HazırlamaTarihi,
      record.TeslimEtmeTarihi,
      record.Durum,
    ]);

    // Excel dosyasını oluşturma
    const worksheet = exceljs.utils.aoa_to_sheet([header, ...rows]);
    const workbook = exceljs.utils.book_new();
    exceljs.utils.book_append_sheet(workbook, worksheet, "Seçilmiş Kayıtlar");

    // Excel dosyasını indirme
    exceljs.writeFile(workbook, "seçili kayıtlar.exceljs");
  };

  const handleLogout = async () => {
    try {
      // Backend'e çıkış işlemi için istek gönder
      const response = await fetch("http://127.0.0.1:2431/api/logout", {
        method: "POST",
        credentials: "include", // Çerezleri gönder
      });

      // Eğer istek başarılı değilse hata fırlat
      if (!response.ok) {
        throw new Error("Çıkış işlemi başarısız oldu.");
      }

      // **Kullanıcı bilgilerini tamamen temizle**
      localStorage.removeItem("user"); // localStorage'dan 'user' verisini temizle
      sessionStorage.clear(); // sessionStorage'ı temizle
      setUserId(null); // Context'i sıfırla (örneğin, React Context kullanıyorsanız)

      // **Başarılı çıkış sonrası giriş sayfasına yönlendir**
      window.location.href = "/login"; // Giriş sayfasına yönlendir
    } catch (error) {
      // Hata durumu: Çıkış işleminde bir sorun oluştuysa hata mesajını yazdır
      console.error("Çıkış hatası:", error.message);

      // Kullanıcıyı giriş sayfasına yönlendir
      window.location.href = "/login";
    }
  };

  var idInListe = 1;

  return (
    <>
      {/* <img
        src="/enigma-logo.svg"
        alt="enigma-logo"
        width="300"
        style={{ userSelect: "none", pointerEvents: "none" }}
      /> */}
      <ToolsPanel
        isAuthorized={isAuthorized}
        userRole={userRole}
        handleLogout={handleLogout}
        exportAllRecordsToExcel={exportAllRecordsToExcel}
        exportFilteredRecordsToExcel={exportFilteredRecordsToExcel}
        exportSelectedRecordsToExcel={exportSelectedRecordsToExcel}
        setFiltre={setFiltre}
        setGarantiFiltre={setGarantiFiltre}
        setFiltreTarihi={setFiltreTarihi}
        setSearchTerm={setSearchTerm}
        searchTerm={searchTerm}
        handleSearch={handleSearch}
        filteredResults={filteredResults}
        sortConfig={sortConfig}
        sortData={sortData}
        handleCheckboxChange={handleCheckboxChange}
        formatTarihVeSaat={formatTarihVeSaat}
        selectedRecords={selectedRecords}
        setSelectedRecords={exportSelectedRecordsToExcel}
      />
      {/*<div style={{ position: "relative" }}>
        {serverRestarted && (
          <div
            className="alert alert-danger w-50"
            style={{
              position: "fixed",
              top: "15%",
              marginLeft: "10px",
              zIndex: 9999,
            }}
          >
            Sunucu yeniden başlatılmış veya oturumunuz geçersiz.
            <br />
            Lütfen tekrar giriş yapınız. <a href="/login">Giriş</a> sayfasına
            git
          </div>
        )}
      </div>*/}
      <div className="table mt-1">
        {filteredResults.length > 0 ? (
          <table
            border="1"
            cellPadding="5"
            cellSpacing="0"
            className="w-100 table-striped"
          >
            <thead>
              <tr style={{ backgroundColor: "#bdbdbd" }}>
                {[
                  { key: "FishNo", label: "Fis No" },
                  { key: "AdSoyad", label: "Ad Soyad" },
                  { key: "TeslimAlmaTarihi", label: "Teslim Alma Tarihi" },
                  { key: "TelNo", label: "TelNo" },
                  { key: "Urun", label: "Ürün" },
                  { key: "Marka", label: "Marka" },
                  { key: "Model", label: "Model" },
                  { key: "SeriNo", label: "Seri No" },
                  { key: "GarantiDurumu", label: "Garanti Durum" },
                  { key: "TeslimAlan", label: "Teslim Alan" },
                  { key: "Teknisyen", label: "Teknisyen" },
                  { key: "Sorunlar", label: "Sorun" },
                  { key: "Aciklama", label: "Açıklama" },
                  { key: "Yapilanlar", label: "Yapılanlar" },
                  { key: "Maliyet", label: "Maliyet" },
                  { key: "Ucret", label: "Ücret" },
                  { key: "HazirlamaTarihi", label: "Hazırlama Tarihi" },
                  { key: "TeslimEtmeTarihi", label: "Teslim Etme Tarihi" },
                  { key: "Durum", label: "Durum" },
                ].map(({ key, label }) => (
                  <th
                    key={key}
                    onClick={() => sortData(key)}
                    style={{ cursor: "pointer" }}
                  >
                    {label}
                    {sortConfig.key === key &&
                      (sortConfig.direction === "asc" ? " ▲" : " ▼")}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filteredResults
                .filter((recordS) => recordS.Durum !== "Teslim Edildi")
                .map((recordS, index) => (
                  <tr key={recordS.FishNo || `recordS-${index}`}>
                    <td>
                      <a
                        className="btn btn-sm btn-secondary d-block mb-2 fs-3"
                        href={`/product-info/${
                          recordS.FishNo - 1 || index - 1
                        }`}
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        {recordS.FishNo}
                      </a>
                      <span className="glyphicon d-block mb-2">
                        #{idInListe++}
                      </span>
                      <input
                        type="checkbox"
                        name="selected-product"
                        id={`selected-product-${recordS.FishNo}`}
                        onChange={(e) => handleCheckboxChange(recordS, e)}
                        className="form-check-input"
                        style={{ width: "20px", height: "20px" }}
                      />
                    </td>
                    <td>{recordS.AdSoyad || "Bilinmiyor"}</td>
                    <td>
                      {formatTarihVeSaat(recordS.TeslimAlmaTarihi) ||
                        "Bilinmiyor"}
                    </td>
                    <td>{recordS.TelNo || "Bilinmiyor"}</td>
                    <td>{recordS.Urun || "Bilinmiyor"}</td>
                    <td>{recordS.Marka || "Bilinmiyor"}</td>
                    <td>{recordS.Model || "Bilinmiyor"}</td>
                    <td>{recordS.SeriNo || "Bilinmiyor"}</td>
                    <td>{recordS.GarantiDurumu || "Bilinmiyor"}</td>
                    <td>{recordS.TeslimAlan || "Bilinmiyor"}</td>
                    <td>{recordS.Teknisyen || "Bilinmiyor"}</td>
                    <td>
                      {recordS?.Sorunlar?.length > 100 ? (
                        <>
                          <span className="text-break">
                            {acikDetaylar[index]
                              ? recordS.Sorunlar
                              : `${recordS.Sorunlar.slice(0, 50)}...`}
                          </span>
                          <button
                            onClick={() => toggleDetay(index)}
                            className="btn btn-sm btn-info mt-1"
                          >
                            {acikDetaylar[index] ? "Daha Az" : "Daha Fazla"}
                          </button>
                        </>
                      ) : (
                        <span>{recordS.Sorunlar || ""}</span>
                      )}
                    </td>
                    <td>
                      {recordS.Aciklama?.length > 100 ? (
                        <>
                          <span className="text-break">
                            {acikAciklama[index]
                              ? recordS.Aciklama
                              : `${recordS.Aciklama.slice(0, 50)}...`}
                          </span>
                          <button
                            onClick={() => toggleAciklama(index)}
                            className="btn btn-sm btn-info mt-1"
                          >
                            {acikAciklama[index] ? "Daha Az" : "Daha Fazla"}
                          </button>
                        </>
                      ) : (
                        <span>{recordS.Aciklama || ""}</span>
                      )}
                    </td>
                    <td>
                      {recordS?.Yapilanlar?.length > 100 ? (
                        <>
                          <span className="text-break">
                            {acikYapilanlar[index]
                              ? recordS.Yapilanlar
                              : `${recordS.Yapilanlar.slice(0, 50)}...`}
                          </span>
                          <button
                            onClick={() => toggleYapilanlar(index)}
                            className="btn btn-sm btn-info mt-1"
                          >
                            {acikYapilanlar[index] ? "Daha Az" : "Daha Fazla"}
                          </button>
                        </>
                      ) : (
                        <span>{recordS.Yapilanlar || ""}</span>
                      )}
                    </td>
                    <td>MALIYET</td>
                    <td>{recordS.Ucret}₺</td>
                    <td>
                      {formatTarihVeSaat(recordS.HazirlamaTarihi) ||
                        "Daha Belirtilmedi"}
                    </td>
                    <td>
                      {formatTarihVeSaat(recordS.TeslimEtmeTarihi) ||
                        "Daha Belirtilmedi"}
                    </td>
                    <td id="gitdegistirya">
                      <span
                        id="estetik"
                        className={(() => {
                          const statusClasses = {
                            Onarılıyor: "onariliyor",
                            Tamamlandı: "tamamlandi",
                            Bekliyor: "bklyr",
                            "İade Edildi": "iade-edildi",
                            "Teslim Edildi": "teslim-edildi",
                            "Onay Bekliyor": "onay-bekliyor",
                            "Yedek Parça Bekliyor": "yedek-parca",
                            "Problemli Ürün": "problemli-urun",
                            "Teslim Alınmadı": "teslim-alinmadi",
                            Hazırlanıyor: "hazirlaniyor",
                            "Arıza Tespiti": "ariza-tespiti",
                            "Değişim Tamamlandı": "degisim-tamamlandi",
                            Faturalandı: "faturalandi",
                            "Garantili Onarım": "garantili-onarim",
                            "Teslim Durumu": "teslim-durumu",
                            "Hurdaya Ayrıldı": "hurdaya-ayrildi",
                            "İade Tamamlandı": "iade-tamamlandi",
                            "İade Toplanıyor": "iade-toplaniyor",
                            Kiralama: "kiralama",
                            "Montaj Yapılacak": "montaj-yapilacak",
                            "Onarım Aşamasında": "onarim-asamasinda",
                            "Onay Durumu": "onay-durumu",
                            "Parça Durumu": "parca-durumu",
                            "Periyodik Bakım": "periyodik-bakim",
                            "Satın Alındı": "satin-alindi",
                            "Servis Durumu": "servis-durumu",
                            "Sipariş Durumu": "siparis-durumu",
                            "Tahsilat Bekliyor": "tahsilat-bekliyor",
                            "Ücret Bildirilecek": "ucret-bildirilecek",
                          };
                          return statusClasses[recordS?.Durum] || ""; // recordS null olabilir, o yüzden optional chaining (?.) kullandım.
                        })()}
                      >
                        {recordS?.Durum}
                      </span>
                    </td>

                    <td id="gitdegistirya" className={statusClass}>
                      <span id="estetik">{recordS.Durum}</span>
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        ) : (
          <table
            border="1"
            cellPadding="5"
            cellSpacing="0"
            className="table table-striped table-responsive"
          >
            <thead className="thead-dark">
              <tr>
                {[
                  { key: "FishNo", label: "Fis No" },
                  { key: "AdSoyad", label: "Ad Soyad" },
                  { key: "TeslimAlmaTarihi", label: "Teslim Alma Tarihi" },
                  { key: "TelNo", label: "TelNo" },
                  { key: "Urun", label: "Ürün" },
                  { key: "Marka", label: "Marka" },
                  { key: "Model", label: "Model" },
                  { key: "SeriNo", label: "Seri No" },
                  { key: "GarantiDurumu", label: "Garanti Durum" },
                  { key: "TeslimAlan", label: "Teslim Alan" },
                  { key: "Teknisyen", label: "Teknisyen" },
                  { key: "Sorunlar", label: "Sorun" },
                  { key: "Aciklama", label: "Açıklama" },
                  { key: "Yapilanlar", label: "Yapılanlar" },
                  { key: "Maliyet", label: "Maliyet" },
                  { key: "Ucret", label: "Ücret" },
                  { key: "HazirlamaTarihi", label: "Hazırlama Tarihi" },
                  { key: "TeslimEtmeTarihi", label: "Teslim Etme Tarihi" },
                  { key: "Durum", label: "Durum" },
                ].map(({ key, label }) => (
                  <th
                    key={key}
                    onClick={() => sortData(key)}
                    style={{ cursor: "pointer" }}
                  >
                    {label}{" "}
                    {sortConfig.key === key &&
                      (sortConfig.direction === "asc" ? " ▲" : " ▼")}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtrelenmisKayitlar.length > 0 ? (
                filtrelenmisKayitlar
                  .filter((record) => record.Durum !== "Teslim Edildi")
                  .map((record, index) => (
                    <tr key={record.FishNo || `record-${index}`}>
                      <td>
                        <a
                          href={`/product-info/${record.FishNo || index}`}
                          target="_blank"
                          className="btn btn-sm btn-secondary text-start w-100"
                        >
                          {record.FishNo}# | {idInListe++}
                        </a>
                        <span className="glyphicon d-block mb-2"></span>
                        <input
                          type="checkbox"
                          name="selected-product"
                          id={`selected-product-${record.FishNo}`}
                          onChange={(e) => handleCheckboxChange(record, e)}
                          className="form-check-input custom-checkbox"
                          style={{ width: "20px", height: "20px" }}
                        />
                      </td>
                      <td>{record.AdSoyad || "Bilinmiyor"}</td>
                      <td>
                        {formatTarihVeSaat(record.TeslimAlmaTarihi) ||
                          "Bilinmiyor"}
                      </td>
                      <td>{record.TelNo || "Bilinmiyor"}</td>
                      <td>{record.Urun || "Bilinmiyor"}</td>
                      <td>{record.Marka || "Bilinmiyor"}</td>
                      <td>{record.Model || "Bilinmiyor"}</td>
                      <td>{record.SeriNo || "Bilinmiyor"}</td>
                      <td>{record.GarantiDurumu || "Bilinmiyor"}</td>
                      <td>{record.TeslimAlan || "Bilinmiyor"}</td>
                      <td>{record.Teknisyen || "Bilinmiyor"}</td>
                      <td>
                        {record.Sorunlar?.length > 50 ? (
                          <>
                            <span className="text-break">
                              {record.Sorunlar.slice(0, 50)}...
                            </span>
                            <button className="btn btn-sm btn-info mt-1">
                              Daha Fazla
                            </button>
                          </>
                        ) : (
                          <span>{record.Sorunlar || ""}</span>
                        )}
                      </td>
                      <td>
                        {record.Aciklama?.length > 50 ? (
                          <>
                            <span className="text-break">
                              {record.Aciklama.slice(0, 50)}...
                            </span>
                            <button className="btn btn-sm btn-info mt-1">
                              Daha Fazla
                            </button>
                          </>
                        ) : (
                          <span>{record.Aciklama || ""}</span>
                        )}
                      </td>
                      <td>
                        {record.Yapilanlar?.length > 50 ? (
                          <>
                            <span className="text-break">
                              {record.Yapilanlar.slice(0, 50)}...
                            </span>
                            <button className="btn btn-sm btn-info mt-1">
                              Daha Fazla
                            </button>
                          </>
                        ) : (
                          <span>{record.Yapilanlar || ""}</span>
                        )}
                      </td>
                      <td>MALIYET</td>
                      <td>{record.Ucret || "0"}₺</td>
                      <td>
                        {formatTarihVeSaat(record.HazirlamaTarihi) ||
                          "Daha Belirtilmedi"}
                      </td>
                      <td>
                        {formatTarihVeSaat(record.TeslimEtmeTarihi) ||
                          "Daha Belirtilmedi"}
                      </td>
                      <td id="gitdegistirya" className="durum-container">
                        <span
                          className={(() => {
                            const statusClasses = {
                              Onarılıyor: "onariliyor",
                              Tamamlandı: "tamamlandi",
                              Bekliyor: "bklyr",
                              "İade Edildi": "iade-edildi",
                              "Teslim Edildi": "teslim-edildi",
                              "Onay Bekliyor": "onay-bekliyor",
                              "Yedek Parça Bekliyor": "yedek-parca",
                              "Problemli Ürün": "problemli-urun",
                              "Teslim Alınmadı": "teslim-alinmadi",
                              Hazırlanıyor: "hazirlaniyor",
                              "Arıza Tespiti": "ariza-tespiti",
                              "Değişim Tamamlandı": "degisim-tamamlandi",
                              Faturalandı: "faturalandi",
                              "Garantili Onarım": "garantili-onarim",
                              "Teslim Durumu": "teslim-durumu",
                              "Hurdaya Ayrıldı": "hurdaya-ayrildi",
                              "İade Tamamlandı": "iade-tamamlandi",
                              "İade Toplanıyor": "iade-toplaniyor",
                              Kiralama: "kiralama",
                              "Montaj Yapılacak": "montaj-yapilacak",
                              "Onarım Aşamasında": "onarim-asamasinda",
                              "Onay Durumu": "onay-durumu",
                              "Parça Durumu": "parca-durumu",
                              "Periyodik Bakım": "periyodik-bakim",
                              "Satın Alındı": "satin-alindi",
                              "Servis Durumu": "servis-durumu",
                              "Sipariş Durumu": "siparis-durumu",
                              "Tahsilat Bekliyor": "tahsilat-bekliyor",
                              "Ücret Bildirilecek": "ucret-bildirilecek",
                            };
                            return statusClasses[record?.Durum] || "";
                          })()}
                        >
                          {record?.Durum}
                        </span>
                        {isAuthorized && userRole === "admin" ? (
                          <button
                            onClick={() => navigate(`/record/${record.FishNo}`)}
                            className="duzenle-btn"
                          >
                            <MdEditSquare />
                          </button>
                        ) : null}
                      </td>
                    </tr>
                  ))
              ) : (
                <tr className="bg-danger text-danger">
                  <td colSpan="19">Filtreye uygun kayıt bulunamadı.</td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
