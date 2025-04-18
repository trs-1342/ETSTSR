import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import "../css/RecordFormPage.css";

// Verilen tarih değerini "gün/ay/yıl saat:dakika" formatına çevirir
function formatTarihVeSaat(tarih) {
  if (!tarih) return "Bilinmiyor";

  const parsedDate = new Date(tarih);
  if (isNaN(parsedDate.getTime())) {
    return tarih; // Geçersizse olduğu gibi döndür
  }

  const year = parsedDate.getFullYear();
  const month = String(parsedDate.getMonth() + 1).padStart(2, "0");
  const day = String(parsedDate.getDate()).padStart(2, "0");
  const hours = String(parsedDate.getHours()).padStart(2, "0");
  const minutes = String(parsedDate.getMinutes()).padStart(2, "0");

  return `${day}/${month}/${year} ${hours}:${minutes}`;
}

export default function EditPage() {
  const { fishNo } = useParams();
  const navigate = useNavigate();

  const [kayit, setKayit] = useState(null);
  const [hata, setHata] = useState("");

  // Net Ücret (KDV Hariç)
  const [ucret, setUcret] = useState(0);
  // KDV Oranı (%20 varsayılan)
  const [kdv, setKdv] = useState(20);
  // KDV Dahil Toplam
  const [totalPrice, setTotalPrice] = useState(0);

  // (İsteğe bağlı) Yetki kontrolleri
  const [isAuthorized, setIsAuthorized] = useState(false);
  const [userRole, setUserRole] = useState("");

  // -----------------------------
  // 1) Yetki Kontrolü (opsiyonel)
  // -----------------------------
  useEffect(() => {
    const fetchUser = async () => {
      try {
        const response = await fetch(
          "http://192.168.0.201:2431/api/checkAdmin",
          {
            credentials: "include",
          }
        );
        if (response.ok) {
          const data = await response.json();
          setIsAuthorized(data.isAuthorized);
          setUserRole(data.role);
        } else {
          console.error("Yetki kontrolü başarısız");
        }
      } catch (error) {
        console.error("Yetki kontrolünde hata:", error.message);
      }
    };
    fetchUser();
  }, []);

  // --------------------------------
  // 2) Fiş Kaydı Verisini Sunucudan Çek
  // --------------------------------
  useEffect(() => {
    if (!fishNo) {
      setHata("Fiş numarası bulunamadı.");
      return;
    }

    fetch(`http://192.168.0.201:2431/api/record/${fishNo}`)
      .then((response) => {
        if (!response.ok) {
          throw new Error(`HTTP hata kodu: ${response.status}`);
        }
        return response.json();
      })
      .then((data) => {
        // Tarihleri formatla (görüntü için)
        data.HazirlamaTarihi = data.HazirlamaTarihi
          ? new Date(data.HazirlamaTarihi).toLocaleDateString("tr-TR")
          : "";
        data.TeslimEtmeTarihi = data.TeslimEtmeTarihi
          ? new Date(data.TeslimEtmeTarihi).toLocaleDateString("tr-TR")
          : "";

        setKayit(data);

        // Veritabanından KDV DAHİL olarak gelen tutarı net'e dönüştür:
        // data.Ucret => KDV Dahil, data.kdv => KDV Oranı
        const totalFromDB = parseFloat(data.Ucret) || 0;
        const kdvFromDB = parseFloat(data.kdv) || 20;

        // Net ücret = (KDV dahil) / (1 + (kdv/100))
        const netUcret = totalFromDB / (1 + kdvFromDB / 100);

        setUcret(netUcret);
        setKdv(kdvFromDB);
      })
      .catch((error) => {
        setHata(`Veri çekme hatası: ${error.message}`);
        console.error("Veri çekme hatası:", error);
      });
  }, [fishNo]);

  // -------------------------------------
  // 3) Net Ücret veya KDV Değişince Toplamı Hesapla
  // -------------------------------------
  useEffect(() => {
    // KDV Dahil = net + (net*(kdv/100)) = net*(1 + kdv/100)
    const newTotal = ucret * (1 + kdv / 100);
    setTotalPrice(newTotal);
  }, [ucret, kdv]);

  // -------------------------------------
  // 4) Input değişimleri
  // -------------------------------------
  // Net ücret (KDV hariç) girişi
  const handleUcretChange = (e) => {
    const newUcret = parseFloat(e.target.value) || 0;
    setUcret(newUcret);
  };

  // KDV oranı girişi
  const handleKdvChange = (e) => {
    const newKdv = parseFloat(e.target.value) || 0;
    setKdv(newKdv);
  };

  // Checkbox (Hazırlama/TeslimEtme) kontrolü
  const handleDateToggle = (fieldName, isChecked) => {
    setKayit((prev) => ({
      ...prev,
      [fieldName]: isChecked ? new Date().toISOString() : null,
    }));
  };

  // Diğer alanlar (AdSoyad, Durum, vb.)
  const handleInputChange = (e) => {
    const { name, value, type, checked } = e.target;
    setKayit((prev) => {
      let updatedValue = type === "checkbox" ? checked : value;

      // HazirlamaTarihi/TeslimEtmeTarihi işaretlendiğinde anlık tarih atama
      if (
        (name === "HazirlamaTarihi" || name === "TeslimEtmeTarihi") &&
        checked
      ) {
        updatedValue = new Date().toISOString();
      }
      return {
        ...prev,
        [name]: updatedValue,
      };
    });
  };

  // -------------------------------------
  // 5) Kaydet Butonu
  // -------------------------------------
  const handleSave = () => {
    if (!kayit) {
      alert("Güncellenmek için geçerli veri bulunamadı.");
      return;
    }

    // Veritabanına tekrar KDV Dahil rakam ve kdv oranı kaydetmek istersek:
    // Ucret => totalPrice (KDV Dahil)
    // kdv   => kdv (oran)
    const finalData = {
      ...kayit,
      Ucret: totalPrice.toFixed(2), // KDV Dahil
      kdv, // KDV Oranı
    };

    // undefined veya null alanları "" yapalım
    const temizKayit = Object.fromEntries(
      Object.entries(finalData).map(([key, value]) => {
        if (value === undefined) return [key, null];
        if (value === null) return [key, ""];
        return [key, value];
      })
    );

    fetch(`http://192.168.0.201:2431/api/record/${fishNo}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(temizKayit),
    })
      .then(async (response) => {
        if (!response.ok) {
          const err = await response.json();
          throw new Error(err.message || "Güncelleme sırasında hata oluştu.");
        }
        return response.json();
      })
      .then(() => {
        alert("Kayıt başarıyla güncellendi!");
        navigate("/");
      })
      .catch((error) => {
        alert(`Güncelleme hatası: ${error.message}`);
        console.error("Güncelleme hatası:", error);
      });
  };

  // Toplamı ekrana yazdırırken iki ondalık gösterim
  const formattedTotalPrice = (val) => {
    if (typeof val === "number" && !isNaN(val)) {
      return val.toFixed(2);
    }
    return "0.00";
  };

  // Hata durumu
  if (hata) {
    return <div>Hata: {hata}</div>;
  }

  // Henüz veri gelmediyse
  if (!kayit) {
    return <div className="container bg-danger rounded">Yükleniyor...</div>;
  }

  // -------------------------------------
  // 6) Arayüz
  // -------------------------------------
  return (
    <div className="container mt-1">
      <h1 className="text-center mb-4">Fiş Düzenleme</h1>
      <h4 className="text-center mb-2">
        <strong>Fiş No: {kayit.fishNo}</strong>
      </h4>

      <form className="row g-3 col-md-12">
        {/* Sol taraf */}
        <div className="col-md-6">
          {/* Ad Soyad - Tel */}
          <div className="row mb-5">
            <div className="col-md-6">
              <label htmlFor="AdSoyad" className="form-label">
                Ad Soyad:
              </label>
              <input
                type="text"
                id="AdSoyad"
                name="AdSoyad"
                placeholder={kayit.AdSoyad || ""}
                className="form-control"
                value={kayit.AdSoyad || ""}
                onChange={handleInputChange}
              />
            </div>
            <div className="col-md-6">
              <label htmlFor="TelNo" className="form-label">
                TelNo:
              </label>
              <input
                type="text"
                id="TelNo"
                name="TelNo"
                placeholder={kayit.TelNo || ""}
                className="form-control"
                value={kayit.TelNo || ""}
                onChange={handleInputChange}
              />
            </div>
          </div>

          {/* Durum - Garanti */}
          <div className="row mb-2">
            <div className="col-md-6 mb-3">
              <label htmlFor="Durum" className="form-label">
                Durumu:
              </label>
              <select
                id="Durum"
                name="Durum"
                className="form-select"
                placeholder={kayit?.Durum || ""}
                onChange={handleInputChange}
              >
                <option value="Bekliyor">Bekliyor</option>
                <option value="Onay Bekliyor">Onay Bekliyor</option>
                <option value="Yedek Parça">Yedek Parça</option>
                <option value="Onarılıyor">Onarılıyor</option>
                <option value="Hazırlanıyor">Hazırlanıyor</option>
                <option value="Tamamlandı">Tamamlandı</option>
                <option value="Teslim Edildi">Teslim Edildi</option>
                <option value="Arıza Tespiti">Arıza Tespiti</option>
                <option value="Değişim Tamamlandı">Değişim Tamamlandı</option>
                <option value="Faturalandı">Faturalandı</option>
                <option value="Garantili Onarım">Garantili Onarım</option>
                <option value="Teslim Durumu">Teslim Durumu</option>
                <option value="Hurdaya Ayrıldı">Hurdaya Ayrıldı</option>
                <option value="İade Tamamlandı">İade Tamamlandı</option>
                <option value="İade Toplanıyor">İade Toplanıyor</option>
                <option value="kiralama">Kiralama</option>
                <option value="Montaj Yapılacak">Montaj Yapılacak</option>
                <option value="Onarım Aşamasında">Onarım Aşamasında</option>
                <option value="Onay Durumu">Onay Durumu</option>
                <option value="Parça Durumu">Parça Durumu</option>
                <option value="Periyodik Bakım">Periyodik Bakım</option>
                <option value="Problemli Ürün">Problemli Ürün</option>
                <option value="Satın Alındı">Satın Alındı</option>
                <option value="Servis Durumu">Servis Durumu</option>
                <option value="Sipariş Durumu">Sipariş Durumu</option>
                <option value="Tahsilat Bekliyor">Tahsilat Bekliyor</option>
                <option value="Ücret Bildirilecek">Ücret Bildirilecek</option>
                <option value="Yedek Parça">Yedek Parça</option>
              </select>
              <p className="fw-light m-0">{kayit.Durum}</p>
            </div>
            <div className="col-md-6 mb-3">
              <label htmlFor="GarantiDurumu" className="form-label">
                Garanti Durumu
              </label>
              <select
                className="form-select"
                id="GarantiDurumu"
                name="GarantiDurumu"
                placeholder={kayit.GarantiDurumu}
                required
                onChange={handleInputChange}
              >
                <option value="" disabled>
                  Garanti Durumu
                </option>
                <option value="Garantili">Garantili</option>
                <option value="Garantisiz">Garantisiz</option>
                <option value="Sözleşmeli">Sözleşmeli</option>
                <option value="Belirsiz">Belirsiz</option>
              </select>
              <p className="fw-light m-0">{kayit.GarantiDurumu}</p>
            </div>
          </div>

          {/* Ücret (Net) - KDV */}
          <div className="row">
            <div className="col-md-12">
              <div className="row">
                <div className="col-md-6">
                  <label htmlFor="ucret" className="form-label">
                    Ücret (Net)
                  </label>
                  <input
                    type="number"
                    id="ucret"
                    value={ucret}
                    placeholder="KDV hariç tutar"
                    onChange={handleUcretChange}
                    className="form-control"
                  />
                </div>
                <div className="col-md-6">
                  <label htmlFor="kdv" className="form-label">
                    KDV (%)
                  </label>
                  <input
                    type="number"
                    id="kdv"
                    value={kdv}
                    className="form-control"
                    onChange={handleKdvChange}
                  />
                </div>
                <div className="col-md-12 mt-3">
                  <p className="fw-light m-0">
                    Toplam Fiyat (Net + KDV): {formattedTotalPrice(totalPrice)}{" "}
                    TL
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Hazırlama - TeslimEtme Checkbox */}
          <div className="row mt-4">
            <div className="col-md-6 custom-checkbox">
              <label htmlFor="HazirlamaTarihi" className="form-label">
                Hazırlandı:
              </label>
              <input
                type="checkbox"
                id="HazirlamaTarihi"
                name="HazirlamaTarihi"
                checked={!!kayit.HazirlamaTarihi}
                onChange={(e) =>
                  handleDateToggle("HazirlamaTarihi", e.target.checked)
                }
              />
              <p className="fw-light m-0">
                {kayit.HazirlamaTarihi
                  ? formatTarihVeSaat(kayit.HazirlamaTarihi)
                  : "Belirtilmedi"}
              </p>
            </div>
            <div className="col-md-6 custom-checkbox">
              <label htmlFor="TeslimEtmeTarihi" className="form-label">
                Teslim Edildi:
              </label>
              <input
                type="checkbox"
                id="TeslimEtmeTarihi"
                name="TeslimEtmeTarihi"
                checked={!!kayit.TeslimEtmeTarihi}
                onChange={(e) =>
                  handleDateToggle("TeslimEtmeTarihi", e.target.checked)
                }
              />
              <p className="fw-light m-0">
                {kayit.TeslimEtmeTarihi
                  ? formatTarihVeSaat(kayit.TeslimEtmeTarihi)
                  : "Belirtilmedi"}
              </p>
            </div>
          </div>
        </div>

        {/* Sağ taraf: Ürün, Marka, Model vs. */}
        <div className="col-md-6">
          <div className="row">
            <div className="col-md-6 mb-4">
              <label htmlFor="Urun" className="form-label">
                Ürün
              </label>
              <select
                className="form-select"
                id="Urun"
                name="Urun"
                placeholder={kayit.Urun || ""}
                required
                onChange={handleInputChange}
              >
                <option value="" disabled>
                  Ürün Seçin
                </option>
                <option value="Bilgisayar">Bilgisayar</option>
                <option value="Laptop">Laptop</option>
                <option value="Kasa">Kasa</option>
                <option value="Ekran Kartı">Ekran Kartı</option>
                <option value="Yazıcı">Yazıcı</option>
              </select>
              <p className="fw-light m-0">{kayit.Urun}</p>
            </div>
            <div className="col-md-6 mb-4">
              <label htmlFor="Marka" className="form-label">
                Marka
              </label>
              <select
                className="form-select"
                id="Marka"
                name="Marka"
                placeholder={kayit.Marka || ""}
                required
                onChange={handleInputChange}
              >
                <option value="" disabled>
                  Marka Seçin
                </option>
                <option value="ACER">ACER</option>
                <option value="AERO COOL">AERO COOL</option>
                <option value="ALL IN ONE">ALL IN ONE</option>
                <option value="APPLE">APPLE</option>
                <option value="ASUS">ASUS</option>
                <option value="BEKO">BEKO</option>
                <option value="BROTHER">BROTHER</option>
                <option value="CANON">CANON</option>
                <option value="CASPER">CASPER</option>
                <option value="CLOOER MASTER">CLOOER MASTER</option>
                <option value="COMPAQ">COMPAQ</option>
                <option value="COOLER MASTER">COOLER MASTER</option>
                <option value="CORSIR">CORSIR</option>
                <option value="DARK">DARK</option>
                <option value="DARK NEON">DARK NEON</option>
                <option value="DELL">DELL</option>
                <option value="DRAGOS">DRAGOS</option>
                <option value="EXCALIBUR">EXCALIBUR</option>
                <option value="EXPER">EXPER</option>
                <option value="FANTECKS">FANTECKS</option>
                <option value="FIJITSU">FIJITSU</option>
                <option value="GIGABYTE">GIGABYTE</option>
                <option value="GRUNDIG">GRUNDIG</option>
                <option value="HAP">HAP</option>
                <option value="HP">HP</option>
                <option value="HUAWEI">HUAWEI</option>
                <option value="IDEAPAD">IDEAPAD</option>
                <option value="IMAC">IMAC</option>
                <option value="INTEL">INTEL</option>
                <option value="KASA">KASA</option>
                <option value="LEGION">LEGION</option>
                <option value="LENOVO">LENOVO</option>
                <option value="MACBOOK">MACBOOK</option>
                <option value="MACBOOK AIR">MACBOOK AIR</option>
                <option value="MONSTER">MONSTER</option>
                <option value="MSI">MSI</option>
                <option value="NZXT">NZXT</option>
                <option value="OMEN">OMEN</option>
                <option value="PACKARD BELL">PACKARD BELL</option>
                <option value="POWERBOOST">POWERBOOST</option>
                <option value="POWERMASTER">POWERMASTER</option>
                <option value="RAZER">RAZER</option>
                <option value="RGB LIT">RGB LIT</option>
                <option value="SAMSUNG">SAMSUNG</option>
                <option value="SAPHIRE">SAPHIRE</option>
                <option value="SDF">SDF</option>
                <option value="SONY">SONY</option>
                <option value="THINKPAD">THINKPAD</option>
                <option value="THERMALTEK">THERMALTEK</option>
                <option value="TOPLAMA">TOPLAMA</option>
                <option value="TOSHIBA">TOSHIBA</option>
                <option value="TURBOX">TURBOX</option>
                <option value="VENTO">VENTO</option>
                <option value="ZALMAN">ZALMAN</option>
                <option value="ZOTAC">ZOTAC</option>
              </select>
              <p className="fw-light m-0">{kayit.Marka}</p>
            </div>
          </div>

          {/* Model - SeriNo - TeslimAlan - Teknisyen */}
          <div className="row">
            <div className="col-md-6">
              <label htmlFor="Model" className="form-label">
                Model
              </label>
              <input
                type="text"
                className="form-control"
                id="Model"
                name="Model"
                placeholder={kayit.Model}
                required
                onChange={handleInputChange}
              />
            </div>
            <div className="col-md-6">
              <label htmlFor="SeriNo" className="form-label">
                Seri No
              </label>
              <input
                type="text"
                className="form-control"
                id="SeriNo"
                name="SeriNo"
                placeholder={kayit.SeriNo}
                required
                onChange={handleInputChange}
              />
            </div>
            <div className="col-6 mt-5">
              <label htmlFor="TeslimAlan" className="form-label">
                Teslim Alan
              </label>
              <input
                type="text"
                className="form-control"
                id="TeslimAlan"
                name="TeslimAlan"
                placeholder={kayit.TeslimAlan}
                required
                onChange={handleInputChange}
              />
            </div>
            <div className="col-6 mt-5">
              <label htmlFor="Teknisyen" className="form-label">
                Teknisyen
              </label>
              <select
                className="form-select"
                id="Teknisyen"
                name="Teknisyen"
                value={kayit.Teknisyen}
                required
                onChange={handleInputChange}
              >
                <option value="" disabled>
                  Teknisyeni Seçin
                </option>
                <option value="İbrahim Bey">İbrahim Bey</option>
                <option value="Emre Bey">Emre Bey</option>
                {/* ... diğer teknisyenler ... */}
              </select>
            </div>
          </div>
        </div>

        {/* Büyük Metin Alanları */}
        <div className="col-12">
          <label htmlFor="BirlikteAlinanlar" className="form-label">
            Birlikte Alınanlar:
          </label>
          <textarea
            id="BirlikteAlinanlar"
            name="BirlikteAlinanlar"
            placeholder={kayit.BirlikteAlinanlar || ""}
            onChange={handleInputChange}
            className="form-control"
            rows="3"
            value={kayit.BirlikteAlinanlar || ""}
            style={{ minHeight: "100px", maxHeight: "300px" }}
          ></textarea>
        </div>
        <div className="col-12">
          <label htmlFor="Sorunlar" className="form-label">
            Sorunlar:
          </label>
          <textarea
            id="Sorunlar"
            name="Sorunlar"
            placeholder={kayit.Sorunlar || ""}
            onChange={handleInputChange}
            className="form-control"
            rows="3"
            value={kayit.Sorunlar || ""}
            style={{ minHeight: "100px", maxHeight: "300px" }}
          ></textarea>
        </div>
        <div className="col-12">
          <label htmlFor="Yapilanlar" className="form-label">
            Yapılanlar
          </label>
          <textarea
            id="Yapilanlar"
            name="Yapilanlar"
            placeholder={kayit.Yapilanlar || ""}
            onChange={handleInputChange}
            className="form-control"
            rows="3"
            value={kayit.Yapilanlar || ""}
            style={{ minHeight: "100px", maxHeight: "300px" }}
          ></textarea>
        </div>
        <div className="col-12">
          <label htmlFor="Aciklama" className="form-label">
            Açıklama:
          </label>
          <textarea
            id="Aciklama"
            name="Aciklama"
            placeholder={kayit.Aciklama || ""}
            onChange={handleInputChange}
            className="form-control"
            rows="3"
            value={kayit.Aciklama || ""}
            style={{ minHeight: "100px", maxHeight: "300px" }}
          ></textarea>
        </div>

        {/* Kaydet Butonu */}
        <div className="col-12 d-flex justify-content-end mt-3">
          <button
            type="button"
            onClick={handleSave}
            className="btn btn-success"
          >
            Kaydet
          </button>
        </div>
      </form>
    </div>
  );
}
