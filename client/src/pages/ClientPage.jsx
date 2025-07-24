import { useEffect, useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";

export default function ClientPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const [record, setRecord] = useState(null);

  useEffect(() => {
    const storedUser = localStorage.getItem("userSession");

    if (storedUser) {
      // ✅ Kullanıcı zaten giriş yapmışsa, localStorage'daki bilgiyi kullan
      setRecord(JSON.parse(storedUser));
    } else {
      // 📌 URL’den gelen `record` bilgisini al
      const queryParams = new URLSearchParams(location.search);
      const recordData = queryParams.get("record");

      if (recordData) {
        // ✅ Kullanıcıyı oturuma kaydet
        const parsedRecord = JSON.parse(decodeURIComponent(recordData));
        localStorage.setItem("userSession", JSON.stringify(parsedRecord));
        setRecord(parsedRecord);
      } else {
        // ❌ Hiçbir oturum yoksa giriş ekranına yönlendir
        navigate("/login-client");
      }
    }
  }, [navigate, location.search]);

  // const handleLogout = () => {
  //   localStorage.removeItem("userSession"); // Oturum temizle
  //   navigate("/login-client"); // Anasayfaya yönlendir
  // };

  const handleLogout = () => {
    localStorage.clear(); // Tüm localStorage'ı sil
    sessionStorage.clear(); // Varsa sessionStorage'ı da sil

    fetch("/logout").then(() => {
      window.location.href = "/login"; // Login sayfasına yönlendir
    });
  };

  // ✅ Yazdır fonksiyonu
  const handlePrint = () => {
    window.print();
  };

  // ✅ PDF oluştur fonksiyonu (Butonları gizler)
  const handleGeneratePDF = () => {
    const input = document.getElementById("record-content");
    const buttons = document.getElementById("pdf-ignore");

    // Butonları geçici olarak gizle
    buttons.style.display = "none";

    html2canvas(input, { scale: 2 }).then((canvas) => {
      const imgData = canvas.toDataURL("image/png");
      const pdf = new jsPDF("p", "mm", "a4");
      const imgWidth = 210;
      const imgHeight = (canvas.height * imgWidth) / canvas.width;
      pdf.addImage(imgData, "PNG", 0, 10, imgWidth, imgHeight);
      pdf.save(`${record?.FishNo || ""}-${record?.AdSoyad || "record"}.pdf`);

      // PDF oluşturulduktan sonra butonları geri göster
      buttons.style.display = "flex";
    });
  };

  return (
    <div className="container mt-5">
      <h1 className="text-center text-primary">Müşteri Kayıt Bilgileri</h1>

      {record ? (
        <div className="card p-4 shadow">
          <p>
            <strong>Fish No:</strong> {record.FishNo}
          </p>
          <p>
            <strong>Ad Soyad:</strong> {record.AdSoyad}
          </p>
          <p>
            <strong>Teslim Alma Tarihi:</strong> {record.TeslimAlmaTarihi}
          </p>
          <p>
            <strong>Telefon No:</strong> {record.TelNo}
          </p>
          <p>
            <strong>Ürün:</strong> {record.Urun}
          </p>
          <p>
            <strong>Marka:</strong> {record.Marka}
          </p>
          <p>
            <strong>Model:</strong> {record.Model}
          </p>
          <p>
            <strong>Seri No:</strong> {record.SeriNo}
          </p>
          <p>
            <strong>Garanti Durumu:</strong> {record.GarantiDurumu}
          </p>
          <p>
            <strong>Teslim Alan:</strong> {record.TeslimAlan}
          </p>
          <p>
            <strong>Teknisyen:</strong> {record.Teknisyen}
          </p>
          <p>
            <strong>Ücret:</strong> {record.Ucret} ₺
          </p>
          <p>
            <strong>Sorunlar:</strong> {record.Sorunlar}
          </p>
          <p>
            <strong>Açıklama:</strong> {record.Aciklama}
          </p>
          <p>
            <strong>Durum:</strong> {record.Durum}
          </p>

          <div
            className="d-flex justify-content-center gap-3 mt-3"
            id="pdf-ignore"
          >
            <button className="btn btn-secondary" onClick={handlePrint}>
              Yazdır
            </button>
            <button className="btn btn-danger" onClick={handleLogout}>
              Çıkış Yap
            </button>
            <button className="btn btn-success" onClick={handleGeneratePDF}>
              PDF Oluştur
            </button>
          </div>
        </div>
      ) : (
        <p className="text-center text-danger">Kayıt bilgisi bulunamadı.</p>
      )}
    </div>
  );
}
