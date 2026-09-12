import React, { useEffect, useState } from "react";

import { API, apiFetch } from "./auth";
import LoginPage from "./LoginPage";
import ChangePasswordPage from "./ChangePasswordPage";


export default function AuthGate({ children }) {
  const [user, setUser] = useState(null);
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    let active = true;

    const unauthorize = () => {
      if (active) {
        sessionStorage.removeItem("compliance_manager_dashboard_cache_v1");
        setUser(null);
      }
    };
    window.addEventListener("auth:unauthorized", unauthorize);

    apiFetch(`${API}/api/auth/me`)
      .then(async response => {
        if (!response.ok) return null;
        const data = await response.json();
        return data.user;
      })
      .then(currentUser => {
        if (active) setUser(currentUser);
      })
      .finally(() => {
        if (active) setChecking(false);
      });

    return () => {
      active = false;
      window.removeEventListener("auth:unauthorized", unauthorize);
    };
  }, []);

  async function logout() {
    try {
      await apiFetch(`${API}/api/auth/logout`, { method: "POST" });
    } finally {
      sessionStorage.removeItem("compliance_manager_dashboard_cache_v1");
      setUser(null);
    }
  }

  if (checking) {
    return <main className="login-page"><div className="login-card">Checking session...</div></main>;
  }

  if (!user) {
    return <LoginPage onAuthenticated={setUser} />;
  }

  if (user.must_change_password) {
    return <ChangePasswordPage onChanged={setUser} onLogout={logout} />;
  }

  return children({ user, logout });
}
