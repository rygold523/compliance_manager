import React, { useEffect, useState } from "react";
import { API, apiFetch } from "../auth";
import { formatDateTime } from "../dateTime";
import { buildDatabaseUserMatrix } from "../databaseMatrix";
import { downloadCsv } from "../tableTools";
import { PaginationControls, SortableHeader, useTableView } from "../tableView";

const EMPTY_SNAPSHOT = {
  access_matrix: { servers: [], rows: [] },
  group_matrix: { servers: [], rows: [] },
  service_account_matrix: { servers: [], rows: [] },
  users: [],
  service_accounts: []
};

let cachedSnapshot = null;

function BadgeList({ values, emptyText = "None", tone = "default" }) {
  if (!values || values.length === 0) {
    return <span className="db-matrix-empty-value">{emptyText}</span>;
  }

  return (
    <span className="db-matrix-badges">
      {values.map(value => (
        <span key={value} className={`db-matrix-badge ${tone}`}>
          {value}
        </span>
      ))}
    </span>
  );
}


function DatabaseUserRoleMatrix({ rows, sources }) {
  const matrix = buildDatabaseUserMatrix(rows, sources);
  const [query, setQuery] = useState("");
  const csvColumns = [
    { key: "username", label: "User", sortValue: user => user.username },
    ...matrix.servers.map(server => ({
      key: server.key,
      label: server.name,
      sortValue: user => {
        const access = user.servers[server.key];
        return access ? `${access.databases.join(" ")} ${access.roles.join(" ")}` : "";
      },
      exportValue: user => {
        const access = user.servers[server.key];
        return access
          ? `Databases: ${access.databases.join("; ")} | Roles: ${access.roles.join("; ")}`
          : "";
      }
    }))
  ];
  const table = useTableView(matrix.users, query, csvColumns, { key: "username", direction: "asc" });

  return (
    <div className="db-matrix-section">
      <h2>Database User and Role Matrix</h2>
      <p className="muted">
        Each row represents one database username. Server columns show the databases and roles available to that user on each configured database server.
      </p>
      <div className="table-toolbar">
        <input type="search" value={query} onChange={event => setQuery(event.target.value)} placeholder="Search users, databases, or roles" />
        <span className="muted">{table.filteredRows.length} of {matrix.users.length}</span>
        <button className="secondary" disabled={!table.filteredRows.length} onClick={() => downloadCsv("database-user-role-matrix.csv", csvColumns, table.sortedRows)}>Export CSV</button>
      </div>
      <div className="db-matrix-wrap">
        <table className="table db-matrix-table">
          <thead>
            <tr>
              {csvColumns.map((column, index) => <SortableHeader key={column.key} column={column} sort={table.sort} onSort={table.toggleSort} className={index === 0 ? "db-matrix-user-column" : ""} />)}
            </tr>
          </thead>
          <tbody>
            {table.filteredRows.length === 0 ? (
              <tr>
                <td colSpan={matrix.servers.length + 1}>
                  No database IAM evidence collected.
                </td>
              </tr>
            ) : (
              table.pagedRows.map(user => (
                <tr key={user.username}>
                  <th scope="row" className="db-matrix-user-column">
                    {user.username}
                  </th>
                  {matrix.servers.map(server => {
                    const access = user.servers[server.key];
                    return (
                      <td key={server.key}>
                        {!access ? (
                          <span className="db-matrix-no-access">—</span>
                        ) : (
                          <div className="db-matrix-cell">
                            <div className="db-matrix-cell-line">
                              <span className="db-matrix-label">Databases</span>
                              <BadgeList values={access.databases} emptyText="None" />
                            </div>
                            <div className="db-matrix-cell-line">
                              <span className="db-matrix-label">Roles</span>
                              <BadgeList values={access.roles} emptyText="None" tone="role" />
                            </div>
                            <span className="db-matrix-last-seen">
                              Last seen {formatDateTime(access.lastSeenAt)}
                            </span>
                          </div>
                        )}
                      </td>
                    );
                  })}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
      <PaginationControls {...table} total={table.sortedRows.length} visibleCount={table.pagedRows.length} />
    </div>
  );
}


function DatabasePrivilegeMatrix({ rows, sources }) {
  const matrix = buildDatabaseUserMatrix(rows, sources);
  const [query, setQuery] = useState("");
  const csvColumns = [
    { key: "username", label: "User", sortValue: user => user.username },
    ...matrix.servers.map(server => ({
      key: server.key,
      label: server.name,
      sortValue: user => (user.servers[server.key]?.privileges || []).join(" "),
      exportValue: user => (user.servers[server.key]?.privileges || []).join("; ")
    }))
  ];
  const table = useTableView(matrix.users, query, csvColumns, { key: "username", direction: "asc" });

  return (
    <div className="db-matrix-section">
      <h2>Database Server Privilege Matrix</h2>
      <p className="muted">
        Elevated server-level capabilities are separated from ordinary database access for faster privileged-access review.
      </p>
      <div className="table-toolbar">
        <input type="search" value={query} onChange={event => setQuery(event.target.value)} placeholder="Search users or privileges" />
        <span className="muted">{table.filteredRows.length} of {matrix.users.length}</span>
        <button className="secondary" disabled={!table.filteredRows.length} onClick={() => downloadCsv("database-privilege-matrix.csv", csvColumns, table.sortedRows)}>Export CSV</button>
      </div>
      <div className="db-matrix-wrap">
        <table className="table db-matrix-table privilege-matrix-table">
          <thead>
            <tr>
              {csvColumns.map((column, index) => <SortableHeader key={column.key} column={column} sort={table.sort} onSort={table.toggleSort} className={index === 0 ? "db-matrix-user-column" : ""} />)}
            </tr>
          </thead>
          <tbody>
            {table.filteredRows.length === 0 ? (
              <tr>
                <td colSpan={matrix.servers.length + 1}>
                  No database privilege evidence collected.
                </td>
              </tr>
            ) : (
              table.pagedRows.map(user => (
                <tr key={user.username}>
                  <th scope="row" className="db-matrix-user-column">
                    {user.username}
                  </th>
                  {matrix.servers.map(server => {
                    const access = user.servers[server.key];
                    return (
                      <td key={server.key}>
                        {!access ? (
                          <span className="db-matrix-no-access">—</span>
                        ) : (
                          <BadgeList
                            values={access.privileges}
                            emptyText="No elevated privileges"
                            tone="privilege"
                          />
                        )}
                      </td>
                    );
                  })}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
      <PaginationControls {...table} total={table.sortedRows.length} visibleCount={table.pagedRows.length} />
    </div>
  );
}

function MatrixTable({ title, data, emptyText }) {
  const servers = data?.servers || [];
  const rows = data?.rows || [];
  const [query, setQuery] = useState("");
  const columns = [
    { key: "username", label: "UserName" },
    ...servers.map(server => ({ key: server, label: server }))
  ];
  const table = useTableView(rows, query, columns, { key: "username", direction: "asc" });

  return (
    <div style={{ marginBottom: "30px" }}>
      <h2>{title}</h2>
      <div className="table-toolbar">
        <input type="search" value={query} onChange={event => setQuery(event.target.value)} placeholder="Search IAM records" />
        <span className="muted">{table.filteredRows.length} of {rows.length}</span>
        <button className="secondary" disabled={!table.filteredRows.length} onClick={() => downloadCsv(`${title.toLowerCase().replace(/[^a-z0-9]+/g, "-")}.csv`, columns, table.sortedRows)}>Export CSV</button>
      </div>
      <div style={{ overflowX: "auto" }}>
        <table className="table">
          <thead>
            <tr>
              {columns.map(column => <SortableHeader key={column.key} column={column} sort={table.sort} onSort={table.toggleSort} />)}
            </tr>
          </thead>
          <tbody>
            {table.filteredRows.length === 0 ? (
              <tr>
                <td colSpan={servers.length + 1}>{emptyText}</td>
              </tr>
            ) : (
              table.pagedRows.map(row => (
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
      <PaginationControls {...table} total={table.sortedRows.length} visibleCount={table.pagedRows.length} />
    </div>
  );
}

function DetailTable({ title, rows, service }) {
  const [query, setQuery] = useState("");
  const columns = [
    { key: "asset_id", label: "Server" },
    { key: "username", label: "User" },
    { key: "uid", label: "UID" },
    { key: "home", label: "Home" },
    { key: "shell", label: "Shell" },
    { key: "access", label: "Access", exportValue: row => (row.access || []).join("; ") },
    { key: "groups", label: "Groups", exportValue: row => (row.groups || []).join("; ") }
  ];
  const table = useTableView(rows, query, columns, { key: "asset_id", direction: "asc" });
  return (
    <div style={{ marginBottom: "30px" }}>
      <h2>{title}</h2>
      <div className="table-toolbar">
        <input type="search" value={query} onChange={event => setQuery(event.target.value)} placeholder="Search IAM details" />
        <span className="muted">{table.filteredRows.length} of {rows.length}</span>
        <button className="secondary" disabled={!table.filteredRows.length} onClick={() => downloadCsv(`${title.toLowerCase().replace(/[^a-z0-9]+/g, "-")}.csv`, columns, table.sortedRows)}>Export CSV</button>
      </div>
      <div style={{ overflowX: "auto" }}>
        <table className="table">
          <thead>
            <tr>
              {columns.map(column => <SortableHeader key={column.key} column={column} sort={table.sort} onSort={table.toggleSort} />)}
            </tr>
          </thead>
          <tbody>
            {table.filteredRows.length === 0 ? (
              <tr>
                <td colSpan="7">
                  {service
                    ? "No service accounts loaded."
                    : "No user accounts loaded."}
                </td>
              </tr>
            ) : (
              table.pagedRows.map((user, index) => (
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
      <PaginationControls {...table} total={table.sortedRows.length} visibleCount={table.pagedRows.length} />
    </div>
  );
}

export default function IAM({ canCollect = false }) {
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
    const response = await apiFetch(`${API}${path}`, options);
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
            {canCollect && (
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
            )}
            <span className="collector-summary">
              {collectorStatus
                ? `${collectorStatus.enabled_sources} enabled source(s), ${databaseSources.length} reporting source(s); minimum collection interval ${collectorStatus.schedule?.minimum_interval_minutes || 5} minutes.`
                : "Database IAM collector unavailable."}
            </span>
          </div>
          <DatabaseUserRoleMatrix
            rows={databaseAccounts}
            sources={databaseSources}
          />
          <DatabasePrivilegeMatrix
            rows={databaseAccounts}
            sources={databaseSources}
          />
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
