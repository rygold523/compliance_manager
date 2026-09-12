import React, { useEffect, useState } from "react";

import { API, apiFetch } from "../auth";
import { buildDatabaseUserMatrix } from "../databaseMatrix";
import { formatDateTime } from "../dateTime";
import { PaginationControls, SortableHeader, useTableView } from "../tableView";


async function jsonResponse(response) {
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || `Request failed with HTTP ${response.status}.`);
  return data;
}

async function fetchJson(path, options) {
  return jsonResponse(await apiFetch(`${API}${path}`, options));
}


function buildReviewItems(users, iam, dbAccess, dbSources, scope) {
  const items = [];
  for (const user of scope.dashboard ? users || [] : []) {
    items.push({ subject_type: "dashboard_user", username: user.username, system: "Compliance Dashboard", access: `Role: ${user.role}; Status: ${user.enabled ? "Enabled" : "Disabled"}`, privileged: user.role === "admin" });
  }
  for (const [subjectType, accounts] of [["server_user", scope.server ? iam.users || [] : []], ["service_account", scope.service ? iam.service_accounts || [] : []]]) {
    for (const user of accounts) {
      items.push({ subject_type: subjectType, username: user.username, system: user.asset_id || "Unknown server", access: `Access: ${(user.access || []).join(", ") || "None"}; Groups: ${(user.groups || []).join(", ") || "None"}`, privileged: (user.groups || []).some(group => ["sudo", "wheel", "administrators"].includes(String(group).toLowerCase())) });
    }
  }
  const matrix = buildDatabaseUserMatrix(scope.database ? dbAccess || [] : [], dbSources || []);
  for (const user of matrix.users) {
    for (const server of matrix.servers) {
      const access = user.servers[server.key];
      if (!access) continue;
      items.push({ subject_type: "database_user", username: user.username, system: server.name, access: `Databases: ${access.databases.join(", ") || "None"}; Roles: ${access.roles.join(", ") || "None"}; Privileges: ${access.privileges.join(", ") || "None"}`, privileged: access.privileges.length > 0 });
    }
  }
  return items;
}


export default function AccessReviews({ currentUser, canManage }) {
  const [campaigns, setCampaigns] = useState([]);
  const [selected, setSelected] = useState(null);
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [drafts, setDrafts] = useState({});
  const [typeFilter, setTypeFilter] = useState("");
  const [showArchived, setShowArchived] = useState(false);
  const [scope, setScope] = useState({ dashboard: true, server: true, database: true, service: false });
  const [form, setForm] = useState({ name: `Quarterly Access Review ${new Date().getFullYear()}`, reviewer: currentUser.display_name || currentUser.username, due_date: new Date(Date.now() + 90 * 86400000).toISOString().slice(0, 10), scope_note: "Dashboard, server, service, and database accounts." });

  async function loadCampaigns() {
    setLoading(true);
    try {
      const data = await jsonResponse(await apiFetch(`${API}/api/access-reviews`));
      setCampaigns(data.campaigns || []);
    } catch (reason) { setError(reason.message); }
    finally { setLoading(false); }
  }

  useEffect(() => { loadCampaigns(); }, []);

  async function openCampaign(id) {
    setBusy(true); setError("");
    try {
      const data = await jsonResponse(await apiFetch(`${API}/api/access-reviews/${id}`));
      setSelected(data.campaign);
      setDrafts(Object.fromEntries((data.campaign.items || []).map(item => [item.item_id, item.comment || ""])));
    } catch (reason) { setError(reason.message); }
    finally { setBusy(false); }
  }

  async function createCampaign(event) {
    event.preventDefault(); setBusy(true); setError(""); setNotice("");
    try {
      const [users, iam, dbAccess, dbSources] = await Promise.all([
        fetchJson("/api/admin/users"),
        fetchJson("/api/iam/snapshot"),
        fetchJson("/api/iam/db-access"),
        fetchJson("/api/iam/db-sources")
      ]);
      const items = buildReviewItems(users.users, iam, dbAccess.accounts, dbSources.sources, scope);
      if (!items.length) throw new Error("No access records are available to review.");
      const data = await jsonResponse(await apiFetch(`${API}/api/access-reviews`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ...form, items }) }));
      setNotice(`Created ${data.campaign.name} with ${data.campaign.items.length} review items.`);
      await loadCampaigns(); await openCampaign(data.campaign.campaign_id);
    } catch (reason) { setError(reason.message); }
    finally { setBusy(false); }
  }

  async function saveDecision(item, decision = item.decision) {
    setBusy(true); setError("");
    try {
      await jsonResponse(await apiFetch(`${API}/api/access-reviews/${selected.campaign_id}/items/${item.item_id}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ decision, comment: drafts[item.item_id] || "" }) }));
      await openCampaign(selected.campaign_id); await loadCampaigns();
    } catch (reason) { setError(reason.message); }
    finally { setBusy(false); }
  }

  async function completeCampaign() {
    if (!window.confirm(`Complete ${selected.name}? Completed campaigns cannot be modified.`)) return;
    setBusy(true); setError("");
    try {
      const data = await jsonResponse(await apiFetch(`${API}/api/access-reviews/${selected.campaign_id}/complete`, { method: "POST" }));
      setSelected(data.campaign); setNotice("Access-review campaign completed."); await loadCampaigns();
    } catch (reason) { setError(reason.message); }
    finally { setBusy(false); }
  }

  async function archiveCampaign() {
    if (!window.confirm(`Archive ${selected.name}? Its frozen evidence and decisions will be retained.`)) return;
    setBusy(true); setError("");
    try {
      const data = await jsonResponse(await apiFetch(`${API}/api/access-reviews/${selected.campaign_id}/archive`, { method: "POST" }));
      setSelected(data.campaign); setNotice("Access-review campaign archived."); await loadCampaigns();
    } catch (reason) { setError(reason.message); }
    finally { setBusy(false); }
  }

  const columns = [
    { key: "username", label: "User" }, { key: "subject_type", label: "Account Type" }, { key: "system", label: "System" },
    { key: "access", label: "Access" }, { key: "privileged", label: "Privileged" }, { key: "decision", label: "Decision" },
    { key: "comment", label: "Reviewer Comment" }, { key: "actions", label: "Actions", sortable: false }
  ];
  const scopedItems = (selected?.items || []).filter(item => !typeFilter || item.subject_type === typeFilter);
  const table = useTableView(scopedItems, query, columns, { key: "username", direction: "asc" });
  const pending = selected?.items?.filter(item => item.decision === "pending").length || 0;

  return <div className="access-reviews">
    <section className="card">
      <div className="user-management-heading"><div><h2>Access Review Campaigns</h2><p className="muted">Certify dashboard, server, service-account, and database access from a frozen IAM snapshot.</p></div><button className="secondary" onClick={loadCampaigns} disabled={loading}>Refresh</button></div>
      {error && <div className="view-error" role="alert">{error}</div>}{notice && <div className="view-status">{notice}</div>}
      {canManage && <form className="access-review-create" onSubmit={createCampaign}>
        <label>Campaign Name<input required value={form.name} onChange={event => setForm({ ...form, name: event.target.value })} /></label>
        <label>Reviewer<input required value={form.reviewer} onChange={event => setForm({ ...form, reviewer: event.target.value })} /></label>
        <label>Due Date<input required type="date" value={form.due_date} onChange={event => setForm({ ...form, due_date: event.target.value })} /></label>
        <label>Scope Note<input value={form.scope_note} onChange={event => setForm({ ...form, scope_note: event.target.value })} /></label>
        <fieldset className="access-review-scope"><legend>Included Accounts</legend>
          <label><input type="checkbox" checked={scope.dashboard} onChange={event => setScope({ ...scope, dashboard: event.target.checked })} />Dashboard users</label>
          <label><input type="checkbox" checked={scope.server} onChange={event => setScope({ ...scope, server: event.target.checked })} />Human server users</label>
          <label><input type="checkbox" checked={scope.database} onChange={event => setScope({ ...scope, database: event.target.checked })} />Database users</label>
          <label><input type="checkbox" checked={scope.service} onChange={event => setScope({ ...scope, service: event.target.checked })} />Service accounts</label>
        </fieldset>
        <button disabled={busy}>Capture Current Access</button>
      </form>}
      <label className="show-archived"><input type="checkbox" checked={showArchived} onChange={event => setShowArchived(event.target.checked)} />Show archived campaigns</label>
      <div className="campaign-list">{loading ? <p>Loading campaigns...</p> : campaigns.filter(campaign => showArchived || campaign.status !== "archived").length === 0 ? <p className="muted">No matching access-review campaigns.</p> : campaigns.filter(campaign => showArchived || campaign.status !== "archived").map(campaign => <button key={campaign.campaign_id} className={`campaign-card ${selected?.campaign_id === campaign.campaign_id ? "selected" : ""}`} onClick={() => openCampaign(campaign.campaign_id)}><strong>{campaign.name}</strong><span>{campaign.status} · Due {campaign.due_date}</span><span>{campaign.total_items - campaign.decision_counts.pending}/{campaign.total_items} decided</span></button>)}</div>
    </section>

    {selected && <section className="card">
      <div className="user-management-heading"><div><h2>{selected.name}</h2><p className="muted">Reviewer: {selected.reviewer} · Created {formatDateTime(selected.created_at)} · {pending} pending</p></div><div className="row-actions"><a className="button-link" href={`${API}/api/access-reviews/${selected.campaign_id}/export`}>Export CSV</a>{canManage && selected.status === "open" && <button disabled={busy || pending > 0} onClick={completeCampaign}>Complete Campaign</button>}{canManage && selected.status !== "archived" && <button className="secondary" disabled={busy} onClick={archiveCampaign}>Archive</button>}</div></div>
      <div className="table-toolbar"><input type="search" value={query} onChange={event => setQuery(event.target.value)} placeholder="Search review items" /><select value={typeFilter} onChange={event => setTypeFilter(event.target.value)}><option value="">All account types</option><option value="dashboard_user">Dashboard users</option><option value="server_user">Human server users</option><option value="database_user">Database users</option><option value="service_account">Service accounts</option></select><span className="muted">{table.filteredRows.length} of {selected.items.length}</span></div>
      <div className="table-wrap"><table><thead><tr>{columns.map(column => <SortableHeader key={column.key} column={column} sort={table.sort} onSort={table.toggleSort} />)}</tr></thead><tbody>{table.pagedRows.map(item => <tr key={item.item_id} className={item.privileged ? "privileged-review-item" : ""}><td>{item.username}</td><td>{item.subject_type}</td><td>{item.system}</td><td>{item.access}</td><td>{item.privileged ? "Yes" : "No"}</td><td>{canManage && selected.status === "open" ? <select value={item.decision} disabled={busy} onChange={event => saveDecision(item, event.target.value)}><option value="pending">Pending</option><option value="retain">Retain</option><option value="remove">Remove</option><option value="investigate">Investigate</option></select> : item.decision}</td><td>{canManage && selected.status === "open" ? <textarea value={drafts[item.item_id] || ""} onChange={event => setDrafts({ ...drafts, [item.item_id]: event.target.value })} /> : item.comment || "—"}</td><td>{canManage && selected.status === "open" ? <button className="secondary" disabled={busy} onClick={() => saveDecision(item)}>Save Note</button> : "Read only"}</td></tr>)}</tbody></table></div>
      <PaginationControls {...table} total={table.sortedRows.length} visibleCount={table.pagedRows.length} />
    </section>}
  </div>;
}
