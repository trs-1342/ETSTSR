import React, { useState } from "react";
import { FaBars, FaTimes, FaArchive } from "react-icons/fa";
import "../css/ToolsPanel.css";

const ToolsPanel = ({
  isAuthorized,
  userRole,
  handleLogout,
  exportAllRecordsToExcel,
  exportFilteredRecordsToExcel,
  exportSelectedRecordsToExcel,
  setFiltre,
  setGarantiFiltre,
  setFiltreTarihi,
  setSearchTerm,
  searchTerm,
}) => {
  const [isPanelOpen, setIsPanelOpen] = useState(false);

  return (
    <>
      {/* Sağ üst menü aç/kapat butonu */}
      <div className="menu-toggle" onClick={() => setIsPanelOpen(!isPanelOpen)}>
        {isPanelOpen ? <FaTimes size={20} /> : <FaBars size={20} />}
      </div>

      {/* Yan menü */}
      <div className={`side-menu ${isPanelOpen ? "open" : ""}`}>
        <h3>Araçlar Paneli</h3>
        <input
          type="text"
          placeholder="Arama yapın..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
        />
        <select onChange={(e) => setFiltre(e.target.value)}>
          <option value="Hepsi">Tüm Durumlar</option>
          <option value="Onarılıyor">Onarılıyor</option>
          <option value="Tamamlandı">Tamamlandı</option>
          <option value="Bekliyor">Bekliyor</option>
        </select>
        <select onChange={(e) => setGarantiFiltre(e.target.value)}>
          <option value="Hepsi">Tüm Garanti Durumları</option>
          <option value="Garantili">Garantili</option>
          <option value="Garantisiz">Garantisiz</option>
        </select>
        <input type="date" onChange={(e) => setFiltreTarihi(e.target.value)} />

        <button className="btn btn-green" onClick={exportAllRecordsToExcel}>
          Tüm Verileri Excele Aktar
        </button>
        <button
          className="btn btn-green"
          onClick={exportFilteredRecordsToExcel}
        >
          Filtreyi Excele Aktar
        </button>
        <button
          className="btn btn-green"
          onClick={exportSelectedRecordsToExcel}
        >
          Seçilmişi Excele Aktar
        </button>

        {isAuthorized && userRole === "admin" && (
          <>
            <button
              className="btn btn-blue"
              onClick={() => (window.location.href = "/add-product")}
            >
              Ürün Ekle
            </button>
            <button
              className="btn btn-blue"
              onClick={() => (window.location.href = "/add-customer")}
            >
              Müşteri/Bayi Ekle
            </button>
            <button
              className="btn btn-yellow"
              onClick={() => (window.location.href = "/settings")}
            >
              Ayarlara Git
            </button>
          </>
        )}

        <a className="btn btn-yellow" href="/delivered-products">
          Teslim Edilmiş Ürünler <FaArchive />
        </a>
        <button className="btn btn-red" onClick={handleLogout}>
          Çıkış Yap
        </button>
      </div>
    </>
  );
};

export default ToolsPanel;
