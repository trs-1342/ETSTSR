// App.jsx
import React, { useEffect, useState } from "react";
import {
  BrowserRouter as Router,
  Routes,
  Route,
  Navigate,
  useLocation,
} from "react-router-dom";

// Context
import { useUser, UserProvider } from "./pages/UserContext";

// !!! Bu üç dosya hariç tutuyoruz: UserContext, YouCantSee, usePageAccess

// İSTEDİĞİN TÜM SAYFALARI İMPORT EDİYORUZ:
import HomePage from "./pages/HomePage";
import LoginPanelPage from "./pages/LoginPanelPage";
import NotFoundPage from "./pages/NotFoundPage";
import UnauthorizedPage from "./pages/UnauthorizedPage";
import YouCantSeePage from "./pages/YouCantSee"; // "giremezsin" sayfası

// Eklenen sayfalar:
import AboutPage from "./pages/AboutPage";
import AddCustomerPage from "./pages/AddCustomerPage";
import ClientPage from "./pages/ClientPage";
import ContactPage from "./pages/ContactPage";
import ControlledRecordsPage from "./pages/ControlledRecordsPage";
import AddProductPage from "./pages/AddProductPage";
import DeliveredProductsPage from "./pages/DeliveredProductsPage";
import ShowCostumerRecordsPage from "./pages/ShowCostumerRecordsPage";
import ProductInfoPage from "./pages/ProductInfoPage";
import RecordFormPage from "./pages/RecordFormPage";
import ChangeSettingsPage from "./pages/ChangeSettingsPage";
import AddUserPage from "./pages/AddUserPage";
import EditUserPage from "./pages/EditUserInfoPage";
import SettingsPage from "./pages/SettingsPage";
import ShowUserStatusPage from "./pages/ShowUserStatusPage";
import ShowUserInfoPage from "./pages/ShowUserInfoPage";
import LoginClientPage from "./pages/LoginClientPage";

// Eğer ToolsPanel.jsx ve SidePanelCom.jsx gerçekten birer sayfaysa, onları da ekleyebilirsin.
// import ToolsPanel from "./pages/ToolsPanel";
// import SidePanelCom from "./pages/SidePanelCom";

function AppContent() {
  const { user } = useUser();

  // permissions: tablestatus'tan dönen 0/1 değerleri
  const [permissions, setPermissions] = useState(null);
  const [loading, setLoading] = useState(true);

  const location = useLocation();

  useEffect(() => {
    // Kullanıcı login değilse, tablestatus sorgusu yapmayacağız
    if (!user) {
      setLoading(false);
      return;
    }

    // Admin kullanıcı için tablestatus sorgusuna gerek yok
    if (user.role === "admin") {
      setPermissions(null);
      setLoading(false);
      return;
    }

    // Admin değilse, tablestatus'tan yetkileri çek
    fetch(
      `http://78.188.217.104:2431/api/get-user-permissions/${user.username}`,
      {
        credentials: "include", // session cookie
      }
    )
      .then((res) => {
        if (!res.ok) {
          throw new Error("Yetki bilgisi alınamadı");
        }
        return res.json();
      })
      .then((data) => {
        setPermissions(data);
        setLoading(false);
      })
      .catch((err) => {
        console.error("Kullanıcı yetki bilgisi çekme hatası:", err);
        setLoading(false);
      });
  }, [user]);

  // Belirli bir sayfaya (tablestatus'taki "kolon") erişimi var mı?
  const canAccess = (pageColumnName) => {
    // henüz login değilse
    if (!user) return false;

    // admin ise full access
    if (user.role === "admin") return true;

    // tablestatus yanıtı gelmediyse
    if (!permissions) return false;

    return permissions[pageColumnName] === 1;
  };

  if (loading) {
    return <div style={{ padding: 20, fontSize: 18 }}>Yükleniyor...</div>;
  }

  return (
    <Routes>
      {/* Yetki gerektirmeyen sayfalar */}
      <Route path="/login" element={<LoginPanelPage />} />
      <Route path="/unauthorized" element={<UnauthorizedPage />} />
      <Route path="/about" element={<AboutPage />} />
      <Route path="/contact" element={<ContactPage />} />
      <Route path="/client" element={<ClientPage />} />
      <Route path="/login-client" element={<LoginClientPage />} />

      {/* ShowUserStatusPage: kullanıcıya kendi yetkilerini gösteren sayfa */}
      <Route path="/show-user-status" element={<ShowUserStatusPage />} />

      {/* Kontrollü Kayıtlar (ControlledRecordsPage) */}
      {canAccess("ControlledRecordsPage") ? (
        <Route path="/controlled-records" element={<ControlledRecordsPage />} />
      ) : (
        <Route
          path="/controlled-records"
          element={<Navigate to="/you-cant-see" />}
        />
      )}

      {/* Admin değilse => HomePage izni varsa ana sayfa açılır, yoksa giremez */}
      {canAccess("HomePage") ? (
        <Route path="/" element={<HomePage />} />
      ) : (
        <Route path="/" element={<Navigate to="/you-cant-see" />} />
      )}

      {/* AddCustomerPage */}
      {canAccess("AddCustomerPage") ? (
        <Route path="/add-customer" element={<AddCustomerPage />} />
      ) : (
        <Route path="/add-customer" element={<Navigate to="/you-cant-see" />} />
      )}

      {/* AddProductPage */}
      {canAccess("AddProdPage") ? (
        <Route path="/add-product" element={<AddProductPage />} />
      ) : (
        <Route path="/add-product" element={<Navigate to="/you-cant-see" />} />
      )}

      {/* DeliveredProductsPage */}
      {canAccess("DeliveredProductsPage") ? (
        <Route path="/delivered-products" element={<DeliveredProductsPage />} />
      ) : (
        <Route
          path="/delivered-products"
          element={<Navigate to="/you-cant-see" />}
        />
      )}

      {/* ShowCostumerRecordsPage */}
      {canAccess("ShowCostumerRecordsPage") ? (
        <Route
          path="/show-costumers-records"
          element={<ShowCostumerRecordsPage />}
        />
      ) : (
        <Route
          path="/show-costumers-records"
          element={<Navigate to="/you-cant-see" />}
        />
      )}

      {/* ProductInfoPage */}
      {canAccess("ProductInfoPage") ? (
        <Route path="/product-info/:fishNo" element={<ProductInfoPage />} />
      ) : (
        <Route
          path="/product-info/:fishNo"
          element={<Navigate to="/you-cant-see" />}
        />
      )}

      {/* RecordFormPage */}
      {canAccess("RecordFormPage") ? (
        <Route path="/record/:fishNo" element={<RecordFormPage />} />
      ) : (
        <Route
          path="/record/:fishNo"
          element={<Navigate to="/you-cant-see" />}
        />
      )}

      {/* SettingsPage (varsayım) */}
      {canAccess("SettingsPage") ? (
        <Route path="/settings" element={<SettingsPage />} />
      ) : (
        <Route path="/settings" element={<Navigate to="/you-cant-see" />} />
      )}

      {/* ChangeSettingsPage */}
      {canAccess("ChangeSettingsPage") ? (
        <Route path="/change-settings" element={<ChangeSettingsPage />} />
      ) : (
        <Route
          path="/change-settings"
          element={<Navigate to="/you-cant-see" />}
        />
      )}

      {/* AddUserPage */}
      {canAccess("AddUserPage") ? (
        <Route path="/add-user" element={<AddUserPage />} />
      ) : (
        <Route path="/add-user" element={<Navigate to="/you-cant-see" />} />
      )}

      {/* EditUserPage */}
      {canAccess("EditUserPage") ? (
        <Route path="/edit-user/:id" element={<EditUserPage />} />
      ) : (
        <Route
          path="/edit-user/:id"
          element={<Navigate to="/you-cant-see" />}
        />
      )}
      {/* EditUserPage */}
      {canAccess("ShowUserInfoPage") ? (
        <Route path="/user/:id" element={<ShowUserInfoPage />} />
      ) : (
        <Route path="/user/:id" element={<YouCantSeePage />} />
      )}

      {/* "Giremezsin" sayfası */}
      <Route path="/you-cant-see" element={<YouCantSeePage />} />

      {/* 404 - Bulunamadı */}
      <Route path="*" element={<NotFoundPage />} />
    </Routes>
  );
}

function App() {
  return (
    <UserProvider>
      <Router>
        <AppContent />
      </Router>
    </UserProvider>
  );
}

export default App;
