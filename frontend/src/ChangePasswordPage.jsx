import React, { useState } from "react";

import { API, apiFetch } from "./auth";


export default function ChangePasswordPage({ onChanged, onLogout }) {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function submit(event) {
    event.preventDefault();
    setError("");
    if (newPassword !== confirmation) {
      setError("New passwords do not match.");
      return;
    }
    setSubmitting(true);
    try {
      const response = await apiFetch(`${API}/api/auth/password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          current_password: currentPassword,
          new_password: newPassword
        })
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.detail || "Password change failed.");
      onChanged(data.user);
    } catch (changeError) {
      setError(changeError.message || "Password change failed.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="login-page">
      <section className="login-card" aria-labelledby="password-title">
        <h1 id="password-title">Change password</h1>
        <p>You must replace the temporary password before opening the dashboard.</p>
        <form onSubmit={submit}>
          <label htmlFor="current-password">Current password</label>
          <input id="current-password" type="password" autoComplete="current-password" required value={currentPassword} onChange={event => setCurrentPassword(event.target.value)} />
          <label htmlFor="new-password">New password</label>
          <input id="new-password" type="password" autoComplete="new-password" minLength="14" required value={newPassword} onChange={event => setNewPassword(event.target.value)} />
          <label htmlFor="confirm-password">Confirm new password</label>
          <input id="confirm-password" type="password" autoComplete="new-password" minLength="14" required value={confirmation} onChange={event => setConfirmation(event.target.value)} />
          {error && <div className="login-error" role="alert">{error}</div>}
          <div className="login-actions">
            <button type="submit" disabled={submitting}>{submitting ? "Changing..." : "Change password"}</button>
            <button type="button" className="secondary" onClick={onLogout}>Sign out</button>
          </div>
        </form>
      </section>
    </main>
  );
}
