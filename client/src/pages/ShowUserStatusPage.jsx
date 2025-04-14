// src/pages/ShowUserStatusPage.jsx
import React, { useEffect, useState } from "react";
import { useUser } from "./UserContext";
import { useNavigate } from "react-router-dom";

export default function ShowUserStatusPage() {
  const { user, setUserId } = useUser();
  const navigate = useNavigate();

  // tablestatus verileri (hangi sayfalara gidebiliyor, hangi sütunlara erişebiliyor)
  const [pagePermissions, setPagePermissions] = useState(null);

  // user_settings verileri (örneğin hangi data sütunlarını görebiliyor, selected_columns vs.)
  const [userSettings, setUserSettings] = useState(null);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // Giriş yapmamışsa login'e yönlendir
  useEffect(() => {
    if (!user) {
      navigate("/login");
    }
  }, [user, navigate]);

  // Tablestatus ve user_settings verilerini sunucudan çek
  useEffect(() => {
    if (!user || user.role === "admin") {
      // Admin veya user yoksa loading'i kapatıyoruz
      setLoading(false);
      return;
    }

    const fetchPermissionsAndSettings = async () => {
      try {
        // 1) tablestatus
        const statusRes = await fetch(
          `http://78.188.217.104:2431/api/get-user-permissions/${user.username}`,
          {
            credentials: "include",
          }
        );
        if (!statusRes.ok) {
          throw new Error("Tablestatus bilgilerinde hata oluştu");
        }
        const statusData = await statusRes.json();

        // 2) user_settings (eğer kullanıyorsan)
        // 404 dönerse kullanıcıya ait kaydı yok demektir, ama hata olarak ele almayalım
        const settingsRes = await fetch(
          `http://78.188.217.104:2431/api/get-user-settings/${user.username}`,
          {
            credentials: "include",
          }
        );
        if (!settingsRes.ok && settingsRes.status !== 404) {
          throw new Error("User settings bilgilerinde hata oluştu");
        }

        let settingsData = null;
        if (settingsRes.ok) {
          settingsData = await settingsRes.json();
        }

        setPagePermissions(statusData);
        setUserSettings(settingsData);
      } catch (err) {
        console.error(err);
        setError(
          "Yetki bilgileri alınırken bir hata oluştu. Lütfen sayfayı yenileyiniz."
        );
      } finally {
        setLoading(false);
      }
    };

    fetchPermissionsAndSettings();
  }, [user]);

  // Çıkış işlemi
  const handleLogout = async () => {
    try {
      const response = await fetch("http://78.188.217.104:2431/api/logout", {
        method: "POST",
        credentials: "include",
      });
      if (!response.ok) {
        throw new Error("Çıkış işlemi başarısız oldu.");
      }
      localStorage.removeItem("user");
      sessionStorage.clear();
      if (setUserId) {
        setUserId(null);
      }
      window.location.href = "/login";
    } catch (error) {
      console.error("Çıkış hatası:", error.message);
      window.location.href = "/login";
    }
  };

  if (loading) {
    return (
      <div className="container text-center mt-5">
        <div className="spinner-border text-primary" role="status" />
        <p className="mt-2">Yetkiler yükleniyor...</p>
      </div>
    );
  }

  if (!user) {
    return null; // Henüz user yoksa, login'e yönlendirme veya boş döndür
  }

  // Admin kullanıcısı için panel
  if (user.role === "admin") {
    return (
      <div className="container mt-5">
        <div className="alert alert-success">
          <h2>Hoş geldiniz, {user.username}!</h2>
          <p>
            Admin rolünüz nedeniyle tüm sayfalara ve verilere erişiminiz var.
          </p>
          <hr />
          <a href="/" className="btn btn-primary me-3">
            Anasayfa
          </a>
          <button onClick={handleLogout} className="btn btn-danger">
            Çıkış Yap
          </button>
        </div>
      </div>
    );
  }

  // Admin değilse:
  return (
    <div className="container mt-4">
      <div className="card p-3 shadow-sm">
        <h2 className="mb-3">Kullanıcı Yetki Durumu</h2>
        {error && <div className="alert alert-danger">{error}</div>}
        <p>
          Hoş geldiniz, <strong>{user.username}</strong>! Rol:{" "}
          <strong>{user.role}</strong>
        </p>

        {/* SADECE DEĞERİ 1 OLAN SAYFA ERİŞİMLERİ */}
        <div className="my-3 border-top pt-3">
          <h4>Sayfa Erişimleri (Sadece erişiminiz olanlar)</h4>
          {pagePermissions ? (
            <div className="row">
              {Object.entries(pagePermissions)
                .filter(([key, val]) => key.includes("Page") && val === 1)
                .map(([key]) => (
                  <div key={key} className="col-md-4 mb-2">
                    <div className="card border-success">
                      <div className="card-body">
                        <h6 className="card-title">{key}</h6>
                        <p className="card-text">Erişiminiz Var</p>
                      </div>
                    </div>
                  </div>
                ))}
            </div>
          ) : (
            <p className="text-muted">Sayfa erişim bilgisi bulunamadı.</p>
          )}
        </div>

        {/* SADECE DEĞERİ 1 OLAN SÜTUN ERİŞİMLERİ */}
        <div className="my-3 border-top pt-3">
          <h4>Sütun Erişimleri (Sadece erişiminiz olanlar)</h4>
          {pagePermissions ? (
            <div className="row">
              {Object.entries(pagePermissions)
                .filter(
                  ([key, val]) =>
                    !key.includes("Page") &&
                    !["username", "id"].includes(key) &&
                    val === 1
                )
                .map(([key]) => (
                  <div key={key} className="col-md-3 mb-2">
                    <div className="card border-success">
                      <div className="card-body">
                        <h6 className="card-title">{key}</h6>
                        <p className="card-text">Görebilir/Düzenleyebilir</p>
                      </div>
                    </div>
                  </div>
                ))}
            </div>
          ) : (
            <p className="text-muted">Sütun erişim bilgisi bulunamadı.</p>
          )}
        </div>

        <div className="text-end border-top pt-3">
          <button onClick={handleLogout} className="btn btn-danger">
            Çıkış Yap
          </button>
        </div>
      </div>
    </div>
  );
}
