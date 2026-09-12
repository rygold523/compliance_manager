import React, { useCallback, useEffect, useState } from "react";

import { API, apiFetch } from "../auth";
import { formatDateTime } from "../dateTime";
import { downloadCsv } from "../tableTools";


const EMPTY_CREATE_FORM = {
  username: "",
  display_name: "",
  password: "",
  role: "viewer"
};


async function responseJson(response) {
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.detail || `Request failed with HTTP ${response.status}.`);
  }
  return data;
}


export default function UserManagement({ currentUser }) {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busyUserId, setBusyUserId] = useState(null);
  const [createForm, setCreateForm] = useState(EMPTY_CREATE_FORM);
  const [sessionView, setSessionView] = useState(null);
  const [sessionLoading, setSessionLoading] = useState(false);
  const [includeInactiveSessions, setIncludeInactiveSessions] = useState(true);
  const [auditEvents, setAuditEvents] = useState([]);
  const [auditTotal, setAuditTotal] = useState(0);
  const [auditOffset, setAuditOffset] = useState(0);
  const [auditSearch, setAuditSearch] = useState("");
  const [auditEventType, setAuditEventType] = useState("");
  const [auditLoading, setAuditLoading] = useState(true);
  const [userFilter, setUserFilter] = useState("all");
  const [inactiveDays, setInactiveDays] = useState(90);
  const AUDIT_LIMIT = 50;

  const inactiveCutoff = Date.now() - inactiveDays * 86400000;
  const isDormant = user => user.enabled && !user.inactivity_exempt && new Date(user.last_login_at || user.created_at).getTime() < inactiveCutoff;
  const visibleUsers = users.filter(user => userFilter === "all" || (userFilter === "dormant" && isDormant(user)) || (userFilter === "exempt" && user.inactivity_exempt) || (userFilter === "disabled" && !user.enabled));

  const loadUsers = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const response = await apiFetch(`${API}/api/admin/users`);
      const data = await responseJson(response);
      setUsers(data.users || []);
    } catch (loadError) {
      setError(loadError.message || "Unable to load dashboard users.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadUsers();
  }, [loadUsers]);

  const loadAuditEvents = useCallback(async (offset = auditOffset) => {
    setAuditLoading(true);
    setError("");
    try {
      const parameters = new URLSearchParams({
        offset: String(offset),
        limit: String(AUDIT_LIMIT)
      });
      if (auditSearch.trim()) parameters.set("search", auditSearch.trim());
      if (auditEventType) parameters.set("event_type", auditEventType);
      const response = await apiFetch(`${API}/api/admin/users/audit-events?${parameters}`);
      const data = await responseJson(response);
      setAuditEvents(data.events || []);
      setAuditTotal(data.total || 0);
      setAuditOffset(data.offset || 0);
    } catch (loadError) {
      setError(loadError.message || "Unable to load authentication audit events.");
    } finally {
      setAuditLoading(false);
    }
  }, [auditOffset, auditSearch, auditEventType]);

  useEffect(() => {
    loadAuditEvents(0);
  }, []);

  async function loadSessions(user, includeInactive = includeInactiveSessions) {
    setSessionLoading(true);
    setError("");
    try {
      const response = await apiFetch(
        `${API}/api/admin/users/${user.id}/sessions?include_inactive=${includeInactive}`
      );
      const data = await responseJson(response);
      setSessionView({ user, sessions: data.sessions || [] });
    } catch (loadError) {
      setError(loadError.message || `Unable to load sessions for ${user.username}.`);
    } finally {
      setSessionLoading(false);
    }
  }

  async function revokeSession(session) {
    const user = sessionView.user;
    if (!window.confirm(`Revoke session ${session.id} for ${user.username}?`)) return;
    setSessionLoading(true);
    setError("");
    try {
      const response = await apiFetch(
        `${API}/api/admin/users/${user.id}/sessions/${session.id}/revoke`,
        { method: "POST" }
      );
      await responseJson(response);
      setNotice(`Revoked session ${session.id} for ${user.username}.`);
      await Promise.all([loadSessions(user), loadUsers(), loadAuditEvents(0)]);
    } catch (revokeError) {
      setError(revokeError.message || `Unable to revoke session ${session.id}.`);
    } finally {
      setSessionLoading(false);
    }
  }

  async function createUser(event) {
    event.preventDefault();
    setError("");
    setNotice("");
    try {
      const response = await apiFetch(`${API}/api/admin/users`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(createForm)
      });
      await responseJson(response);
      setCreateForm(EMPTY_CREATE_FORM);
      setNotice("User created. The user must change the temporary password at first login.");
      await loadUsers();
    } catch (createError) {
      setError(createError.message || "Unable to create user.");
    }
  }

  async function updateUser(user, changes) {
    setBusyUserId(user.id);
    setError("");
    setNotice("");
    try {
      const response = await apiFetch(`${API}/api/admin/users/${user.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(changes)
      });
      await responseJson(response);
      setNotice(`Updated ${user.username}.`);
      await loadUsers();
    } catch (updateError) {
      setError(updateError.message || `Unable to update ${user.username}.`);
    } finally {
      setBusyUserId(null);
    }
  }

  async function resetPassword(user) {
    const password = window.prompt(
      `Enter a temporary password for ${user.username}. It must contain at least 14 characters.`
    );
    if (password === null) return;
    if (password.length < 14) {
      setError("Temporary password must contain at least 14 characters.");
      return;
    }
    if (!window.confirm(`Reset the password and revoke all sessions for ${user.username}?`)) {
      return;
    }

    await runUserAction(
      user,
      "reset-password",
      { new_password: password },
      `Password reset for ${user.username}.`
    );
  }

  async function runUserAction(user, action, body, successMessage) {
    setBusyUserId(user.id);
    setError("");
    setNotice("");
    try {
      const response = await apiFetch(
        `${API}/api/admin/users/${user.id}/${action}`,
        {
          method: "POST",
          headers: body ? { "Content-Type": "application/json" } : undefined,
          body: body ? JSON.stringify(body) : undefined
        }
      );
      const data = await responseJson(response);
      setNotice(successMessage || data.message || "Action completed.");
      await loadUsers();
    } catch (actionError) {
      setError(actionError.message || `Unable to update ${user.username}.`);
    } finally {
      setBusyUserId(null);
    }
  }

  async function toggleInactivityExemption(user) {
    let reason = "";
    if (!user.inactivity_exempt) {
      reason = window.prompt(`Enter the business reason for exempting ${user.username} from inactivity controls:`) || "";
      if (!reason.trim()) return;
    }
    await updateUser(user, { inactivity_exempt: !user.inactivity_exempt, inactivity_exemption_reason: reason.trim() });
  }

  async function disableDormantUsers() {
    setError(""); setNotice("");
    try {
      const previewResponse = await apiFetch(`${API}/api/admin/users/disable-dormant`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ inactive_days: inactiveDays, preview: true }) });
      const preview = await responseJson(previewResponse);
      if (!preview.count) { setNotice(`No eligible accounts have been inactive for ${inactiveDays} days.`); return; }
      const names = preview.users.map(user => user.username).join(", ");
      if (!window.confirm(`Disable ${preview.count} dormant account(s) and revoke their sessions?\n\n${names}`)) return;
      const response = await apiFetch(`${API}/api/admin/users/disable-dormant`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ inactive_days: inactiveDays, preview: false }) });
      const result = await responseJson(response);
      setNotice(`Disabled ${result.disabled_count} dormant account(s).`);
      await Promise.all([loadUsers(), loadAuditEvents(0)]);
    } catch (actionError) { setError(actionError.message || "Unable to disable dormant accounts."); }
  }

  return (
    <>
    <section className="card user-management">
      <div className="user-management-heading">
        <div>
          <h2>Dashboard Users</h2>
          <p className="muted">
            Manage local dashboard access. Administrative actions are recorded in the authentication audit log.
          </p>
        </div>
        <button className="secondary" onClick={loadUsers} disabled={loading}>
          Refresh Users
        </button>
      </div>

      {error && <div className="view-error" role="alert">{error}</div>}
      {notice && <div className="view-status" role="status">{notice}</div>}

      <form className="user-create-form" onSubmit={createUser}>
        <h3>Create User</h3>
        <label>
          Username
          <input
            required
            maxLength="128"
            autoComplete="off"
            value={createForm.username}
            onChange={event => setCreateForm({ ...createForm, username: event.target.value })}
          />
        </label>
        <label>
          Display Name
          <input
            required
            maxLength="255"
            value={createForm.display_name}
            onChange={event => setCreateForm({ ...createForm, display_name: event.target.value })}
          />
        </label>
        <label>
          Temporary Password
          <input
            required
            type="password"
            minLength="14"
            maxLength="1024"
            autoComplete="new-password"
            value={createForm.password}
            onChange={event => setCreateForm({ ...createForm, password: event.target.value })}
          />
        </label>
        <label>
          Role
          <select
            value={createForm.role}
            onChange={event => setCreateForm({ ...createForm, role: event.target.value })}
          >
            <option value="viewer">Viewer</option>
            <option value="auditor">Auditor</option>
            <option value="admin">Administrator</option>
          </select>
        </label>
        <div className="user-create-action">
          <button type="submit">Create User</button>
        </div>
      </form>

      <div className="audit-toolbar dormant-controls">
        <label>Inactive threshold
          <select value={inactiveDays} onChange={event => setInactiveDays(Number(event.target.value))}>
            <option value="30">30 days</option><option value="60">60 days</option><option value="90">90 days</option><option value="180">180 days</option><option value="365">365 days</option>
          </select>
        </label>
        <label>Account filter
          <select value={userFilter} onChange={event => setUserFilter(event.target.value)}>
            <option value="all">All accounts</option><option value="dormant">Dormant</option><option value="exempt">Inactivity exempt</option><option value="disabled">Disabled</option>
          </select>
        </label>
        <button type="button" className="danger" onClick={disableDormantUsers}>Review and Disable Dormant</button>
        <span className="muted">{visibleUsers.length} of {users.length} accounts</span>
      </div>

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>User</th>
              <th>Role</th>
              <th>Status</th>
              <th>Last Login (ET)</th>
              <th>Inactivity</th>
              <th>Created (ET)</th>
              <th>Sessions</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan="8">Loading users...</td></tr>
            ) : visibleUsers.length === 0 ? (
              <tr><td colSpan="8">No matching local users found.</td></tr>
            ) : visibleUsers.map(user => {
              const busy = busyUserId === user.id;
              const isCurrentUser = user.id === currentUser.id;
              const locked = user.is_locked === true;
              return (
                <tr key={user.id}>
                  <td>
                    <div>{user.display_name}</div>
                    <div className="muted">{user.username}{isCurrentUser ? " (you)" : ""}</div>
                  </td>
                  <td>
                    <select
                      value={user.role}
                      disabled={busy || isCurrentUser}
                      aria-label={`Role for ${user.username}`}
                      onChange={event => updateUser(user, { role: event.target.value })}
                    >
                      <option value="viewer">Viewer</option>
                      <option value="auditor">Auditor</option>
                      <option value="admin">Administrator</option>
                    </select>
                  </td>
                  <td>
                    <span className={`account-status ${user.enabled ? "enabled" : "disabled"}`}>
                      {user.enabled ? "Enabled" : "Disabled"}
                    </span>
                    {locked && <div className="account-warning">Locked until {formatDateTime(user.locked_until)}</div>}
                    {user.must_change_password && <div className="account-warning">Password change required</div>}
                  </td>
                  <td>{formatDateTime(user.last_login_at)}</td>
                  <td>{user.inactivity_exempt ? <span className="account-status enabled" title={user.inactivity_exemption_reason}>Exempt</span> : isDormant(user) ? <span className="account-status disabled">Dormant</span> : "Current"}</td>
                  <td>{formatDateTime(user.created_at, "Unknown")}</td>
                  <td>{user.active_sessions}</td>
                  <td>
                    <div className="row-actions">
                      <button
                        className={user.enabled ? "danger" : "secondary"}
                        disabled={busy || isCurrentUser}
                        onClick={() => {
                          const action = user.enabled ? "disable" : "enable";
                          if (window.confirm(`${action} ${user.username}?`)) {
                            updateUser(user, { enabled: !user.enabled });
                          }
                        }}
                      >
                        {user.enabled ? "Disable" : "Enable"}
                      </button>
                      <button className="secondary" disabled={busy} onClick={() => resetPassword(user)}>
                        Reset Password
                      </button>
                      <button
                        className="secondary"
                        disabled={busy || !locked}
                        onClick={() => runUserAction(user, "unlock", null, `Unlocked ${user.username}.`)}
                      >
                        Unlock
                      </button>
                      <button
                        className="secondary"
                        disabled={busy || user.active_sessions === 0}
                        onClick={() => {
                          if (window.confirm(`Revoke every active session for ${user.username}?`)) {
                            runUserAction(user, "revoke-sessions", null, `Revoked sessions for ${user.username}.`);
                          }
                        }}
                      >
                        Revoke Sessions
                      </button>
                      <button
                        className="secondary"
                        disabled={busy}
                        onClick={() => loadSessions(user)}
                      >
                        Manage Sessions
                      </button>
                      <button className="secondary" disabled={busy || isCurrentUser} onClick={() => toggleInactivityExemption(user)}>
                        {user.inactivity_exempt ? "Remove Exemption" : "Exempt from Inactivity"}
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>

    <section className="card authentication-audit">
      <div className="user-management-heading">
        <div>
          <h2>Authentication Audit</h2>
          <p className="muted">Review sign-ins, failures, lockouts, password activity, administrative changes, and session revocations.</p>
        </div>
        <button className="secondary" onClick={() => loadAuditEvents(auditOffset)} disabled={auditLoading}>Refresh Audit</button>
      </div>

      <form className="audit-toolbar" onSubmit={event => { event.preventDefault(); loadAuditEvents(0); }}>
        <input type="search" value={auditSearch} onChange={event => setAuditSearch(event.target.value)} placeholder="Search user, event, or source address" />
        <select value={auditEventType} onChange={event => setAuditEventType(event.target.value)} aria-label="Authentication event type">
          <option value="">All event types</option>
          <option value="login_succeeded">Login succeeded</option>
          <option value="login_failed">Login failed</option>
          <option value="logout">Logout</option>
          <option value="password_changed">Password changed</option>
          <option value="user_created">User created</option>
          <option value="user_updated">User updated</option>
          <option value="user_password_reset">Password reset</option>
          <option value="user_unlocked">User unlocked</option>
          <option value="user_session_revoked">Session revoked</option>
          <option value="user_sessions_revoked">All sessions revoked</option>
        </select>
        <button type="submit" disabled={auditLoading}>Apply</button>
        <button type="button" className="secondary" disabled={!auditEvents.length} onClick={() => downloadCsv(
          "authentication-audit.csv",
          [
            { key: "created_at", label: "Timestamp" },
            { key: "event_type", label: "Event Type" },
            { key: "username", label: "User" },
            { key: "source_address", label: "Source Address" },
            { key: "detail", label: "Details" }
          ],
          auditEvents
        )}>Export Page</button>
        <span className="muted">{auditTotal} matching events</span>
      </form>

      <div className="table-wrap">
        <table>
          <thead><tr><th>Timestamp (ET)</th><th>Event</th><th>User</th><th>Source</th><th>Details</th></tr></thead>
          <tbody>
            {auditLoading ? <tr><td colSpan="5">Loading authentication audit...</td></tr> : auditEvents.length === 0 ? <tr><td colSpan="5">No matching authentication events.</td></tr> : auditEvents.map(event => (
              <tr key={event.id}>
                <td>{formatDateTime(event.created_at)}</td>
                <td><span className={`audit-event ${event.event_type === "login_failed" ? "failed" : ""}`}>{event.event_type}</span></td>
                <td>{event.username || "Unknown"}</td>
                <td>{event.source_address || "Unknown"}</td>
                <td><code className="audit-detail">{Object.entries(event.detail || {}).map(([key, value]) => `${key}: ${typeof value === "object" ? JSON.stringify(value) : value}`).join(" | ") || "—"}</code></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="table-pagination">
        <span className="muted">Showing {auditTotal === 0 ? 0 : auditOffset + 1}–{Math.min(auditOffset + auditEvents.length, auditTotal)} of {auditTotal}</span>
        <button className="secondary" disabled={auditLoading || auditOffset === 0} onClick={() => loadAuditEvents(Math.max(0, auditOffset - AUDIT_LIMIT))}>Previous</button>
        <button className="secondary" disabled={auditLoading || auditOffset + AUDIT_LIMIT >= auditTotal} onClick={() => loadAuditEvents(auditOffset + AUDIT_LIMIT)}>Next</button>
      </div>
    </section>

    {sessionView && (
      <div className="modal-backdrop" role="presentation" onMouseDown={event => { if (event.target === event.currentTarget) setSessionView(null); }}>
        <div className="modal session-modal" role="dialog" aria-modal="true" aria-labelledby="session-modal-title">
          <div className="modal-header">
            <h2 id="session-modal-title">Sessions for {sessionView.user.username}</h2>
            <button className="secondary" onClick={() => setSessionView(null)}>Close</button>
          </div>
          <label className="session-filter">
            <input type="checkbox" checked={includeInactiveSessions} onChange={event => { const checked = event.target.checked; setIncludeInactiveSessions(checked); loadSessions(sessionView.user, checked); }} />
            Include expired and revoked sessions
          </label>
          {sessionLoading ? <p>Loading sessions...</p> : (
            <div className="table-wrap">
              <table>
                <thead><tr><th>ID</th><th>Status</th><th>Created (ET)</th><th>Last Activity (ET)</th><th>Expires (ET)</th><th>Source</th><th>Client</th><th>Action</th></tr></thead>
                <tbody>
                  {sessionView.sessions.length === 0 ? <tr><td colSpan="8">No sessions found.</td></tr> : sessionView.sessions.map(session => (
                    <tr key={session.id}>
                      <td>{session.id}</td>
                      <td><span className={`session-status ${session.status}`}>{session.status}</span></td>
                      <td>{formatDateTime(session.created_at)}</td>
                      <td>{formatDateTime(session.last_seen_at)}</td>
                      <td>{formatDateTime(session.expires_at)}</td>
                      <td>{session.source_address || "Unknown"}</td>
                      <td className="session-client" title={session.user_agent || "Unknown"}>{session.user_agent || "Unknown"}</td>
                      <td><button className="danger" disabled={sessionLoading || session.status !== "active"} onClick={() => revokeSession(session)}>Revoke</button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    )}
    </>
  );
}
