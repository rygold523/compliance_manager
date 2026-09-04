import React, { useEffect, useState } from "react";

const API =
  import.meta.env.VITE_API_URL ||
  `${window.location.protocol}//${window.location.hostname}:8000`;

const EMPTY_SNAPSHOT = {
  access_matrix: { servers: [], rows: [] },
  group_matrix: { servers: [], rows: [] },
  service_account_matrix: { servers: [], rows: [] },
  users: [],
  service_accounts: []
};

let cachedSnapshot = null;

function formatDate(value) {
  if (!value) return "Never";

  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : date.toLocaleString();
}

function DatabaseAccessTable({ rows }) {
  return (
    <div style={{ marginBottom: "30px" }}>
      <h2>Database Users and Roles</h2>
      <div style={{ overflowX: "auto" }}>
        <table className="table">
          <thead>
            <tr>
              <th>Source</th>
              <th>Database</th>
              <th>User</th>
              <th>Roles</th>
              <th>Privileged</th>
              <th>Database Privileges</th>
              <th>Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td colSpan="7">
                  No database IAM evidence collected.
                </td>
              </tr>
            ) : (
              rows.map(row => {
                const privilegeLabels = [];
                if (row.superuser) privilegeLabels.push("Superuser");
                if (row.create_role) privilegeLabels.push("Create role");
                if (row.create_database) privilegeLabels.push("Create database");
                if (row.replication) privilegeLabels.push("Replication");
                if (row.bypass_rls) privilegeLabels.push("Bypass RLS");

                const databasePrivileges = (
                  row.database_privileges || []
                ).map(item => {
                  const grants = [];
                  if (item.connect) grants.push("CONNECT");
                  if (item.create) grants.push("CREATE");
                  if (item.temp) grants.push("TEMP");
                  return grants.length
                    ? `${item.database}: ${grants.join(", ")}`
                    : null;
                }).filter(Boolean);

                return (
                  <tr key={`${row.source_key}:${row.username}`}>
                    <td>{row.source_name || row.source_key}</td>
                    <td>{row.database_name || "—"}</td>
                    <td>{row.username}</td>
                    <td>{(row.roles || []).join(", ") || "—"}</td>
                    <td>
                      {privilegeLabels.join(", ") || "No"}
                    </td>
                    <td>
                      {databasePrivileges.join("; ") || "—"}
                    </td>
                    <td>{formatDate(row.last_seen_at)}</td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function MatrixTable({ title, data, emptyText }) {
  const servers = data?.servers || [];
  const rows = data?.rows || [];

  return (
    <div style={{ marginBottom: "30px" }}>
      <h2>{title}</h2>
      <div style={{ overflowX: "auto" }}>
        <table className="table">
          <thead>
            <tr>
              <th>UserName</th>
              {servers.map(server => (
                <th key={server}>{server}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td colSpan={servers.length + 1}>{emptyText}</td>
              </tr>
            ) : (
              rows.map(row => (
                <tr key={row.username}>
                  <td>{row.username}</td>
                  {servers.map(server => (
                    <td key={server}>{row[server] || ""}</td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function DetailTable({ title, rows, service }) {
  return (
    <div style={{ marginBottom: "30px" }}>
      <h2>{title}</h2>
      <div style={{ overflowX: "auto" }}>
        <table className="table">
          <thead>
            <tr>
              <th>Server</th>
              <th>User</th>
              <th>UID</th>
              <th>Home</th>
              <th>Shell</th>
              <th>Access</th>
              <th>Groups</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td colSpan="7">
                  {service
                    ? "No service accounts loaded."
                    : "No user accounts loaded."}
                </td>
              </tr>
            ) : (
              rows.map((user, index) => (
                <tr key={`${user.asset_id}-${user.username}-${index}`}>
                  <td>{user.asset_id}</td>
                  <td>{user.username}</td>
                  <td>{user.uid}</td>
                  <td>{user.home}</td>
                  <td>{user.shell}</td>
                  <td>{(user.access || []).join(", ")}</td>
                  <td>{(user.groups || []).join(", ")}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default function IAM() {
  const [snapshot, setSnapshot] = useState(
    () => cachedSnapshot || EMPTY_SNAPSHOT
  );
  const [loading, setLoading] = useState(!cachedSnapshot);
  const [error, setError] = useState("");
  const [databaseAccounts, setDatabaseAccounts] = useState(
    () => cachedSnapshot?.databaseAccounts || []
  );
  const [databaseSources, setDatabaseSources] = useState(
    () => cachedSnapshot?.databaseSources || []
  );
  const [collectorStatus, setCollectorStatus] = useState(
    () => cachedSnapshot?.collectorStatus || null
  );
  const [collecting, setCollecting] = useState(false);

  async function fetchJson(path, options) {
    const response = await fetch(`${API}${path}`, options);
    if (!response.ok) {
      throw new Error(`${path} returned HTTP ${response.status}`);
    }
    return response.json();
  }

  async function loadDatabaseData(signal) {
    const [access, sources, status] = await Promise.all([
      fetchJson("/api/iam/db-access", { signal }),
      fetchJson("/api/iam/db-sources", { signal }),
      fetchJson("/api/iam/db-collector/status", { signal })
        .catch(() => null)
    ]);

    const accounts = access.accounts || [];
    const sourceRows = sources.sources || [];
    setDatabaseAccounts(accounts);
    setDatabaseSources(sourceRows);
    setCollectorStatus(status);

    return {
      databaseAccounts: accounts,
      databaseSources: sourceRows,
      collectorStatus: status
    };
  }

  useEffect(() => {
    const controller = new AbortController();

    async function loadData() {
      setLoading(true);
      setError("");

      try {
        const [data, databaseData] = await Promise.all([
          fetchJson("/api/iam/snapshot", {
            signal: controller.signal
          }),
          loadDatabaseData(controller.signal)
        ]);
        cachedSnapshot = {
          ...EMPTY_SNAPSHOT,
          ...(data || {}),
          ...databaseData
        };
        setSnapshot(cachedSnapshot);
      } catch (loadError) {
        if (loadError.name !== "AbortError") {
          console.error(loadError);
          setError(String(loadError));
        }
      } finally {
        if (!controller.signal.aborted) {
          setLoading(false);
        }
      }
    }

    loadData();
    return () => controller.abort();
  }, []);

  async function collectDatabaseIam() {
    setCollecting(true);
    setError("");

    try {
      await fetchJson("/api/iam/db-collect", {
        method: "POST"
      });
      const databaseData = await loadDatabaseData();
      cachedSnapshot = {
        ...(cachedSnapshot || EMPTY_SNAPSHOT),
        ...databaseData
      };
    } catch (collectError) {
      setError(collectError.message || String(collectError));
    } finally {
      setCollecting(false);
    }
  }

  return (
    <div>
      <h1>IAM</h1>

      {loading && !cachedSnapshot && (
        <p className="view-status">Loading IAM evidence…</p>
      )}

      {loading && cachedSnapshot && (
        <p className="view-status">Refreshing IAM evidence…</p>
      )}

      {error && (
        <div className="view-error">
          {error}
        </div>
      )}

      {(cachedSnapshot || !loading) && (
        <>
          <MatrixTable
            title="User Access Matrix"
            data={snapshot.access_matrix}
            emptyText="No agent-collected IAM user evidence found."
          />
          <MatrixTable
            title="User Group Assignment Matrix"
            data={snapshot.group_matrix}
            emptyText="No agent-collected IAM user group evidence found."
          />
          <div className="section-actions">
            <button
              onClick={collectDatabaseIam}
              disabled={
                collecting ||
                !collectorStatus ||
                collectorStatus.enabled_sources === 0
              }
            >
              {collecting ? "Collecting…" : "Collect Database IAM Now"}
            </button>
            <span className="collector-summary">
              {collectorStatus
                ? `${collectorStatus.enabled_sources} enabled source(s), ${databaseSources.length} reporting source(s); minimum collection interval ${collectorStatus.schedule?.minimum_interval_minutes || 5} minutes.`
                : "Database IAM collector unavailable."}
            </span>
          </div>
          <DatabaseAccessTable rows={databaseAccounts} />
          <DetailTable
            title="IAM User Evidence Details"
            rows={snapshot.users || []}
            service={false}
          />
          <MatrixTable
            title="Service Account Group Matrix"
            data={snapshot.service_account_matrix}
            emptyText="No service account evidence found."
          />
          <DetailTable
            title="Service Account Evidence Details"
            rows={snapshot.service_accounts || []}
            service={true}
          />
        </>
      )}
    </div>
  );
}
