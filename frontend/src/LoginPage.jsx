import React, { useState } from "react";

import { API, apiFetch } from "./auth";


export default function LoginPage({ onAuthenticated }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function submit(event) {
    event.preventDefault();
    setError("");
    setSubmitting(true);

    try {
      const response = await apiFetch(`${API}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(data.detail || "Login failed.");
      }
      setPassword("");
      onAuthenticated(data.user);
    } catch (loginError) {
      setError(loginError.message || "Login failed.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="login-page">
      <section className="login-card" aria-labelledby="login-title">
        <img
          src="/brand/full-logo-animation-01.gif"
          alt="Iteration Matrix"
          className="login-logo"
        />
        <h1 id="login-title">Compliance Manager</h1>
        <p>Sign in with your local dashboard account.</p>

        <form onSubmit={submit}>
          <label htmlFor="login-username">Username</label>
          <input
            id="login-username"
            name="username"
            value={username}
            onChange={event => setUsername(event.target.value)}
            autoComplete="username"
            autoFocus
            required
          />

          <label htmlFor="login-password">Password</label>
          <input
            id="login-password"
            name="password"
            type="password"
            value={password}
            onChange={event => setPassword(event.target.value)}
            autoComplete="current-password"
            required
          />

          {error && <div className="login-error" role="alert">{error}</div>}

          <button type="submit" disabled={submitting}>
            {submitting ? "Signing in..." : "Sign in"}
          </button>
        </form>
      </section>
    </main>
  );
}
