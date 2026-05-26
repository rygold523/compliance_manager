import React, { useEffect, useState } from "react";

const API = import.meta.env.VITE_API_URL || `${window.location.protocol}//${window.location.hostname}:8000`;

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
                  {service ? "No service accounts loaded." : "No user accounts loaded."}
                </td>
              </tr>
            ) : (
              rows.map((u, idx) => (
                <tr key={`${u.asset_id}-${u.username}-${idx}`}>
                  <td>{u.asset_id}</td>
                  <td>{u.username}</td>
                  <td>{u.uid}</td>
                  <td>{u.home}</td>
                  <td>{u.shell}</td>
                  <td>{(u.access || []).join(", ")}</td>
                  <td>{(u.groups || []).join(", ")}</td>
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
  const [accessMatrix, setAccessMatrix] = useState({ servers: [], rows: [] });
  const [groupMatrix, setGroupMatrix] = useState({ servers: [], rows: [] });
  const [serviceMatrix, setServiceMatrix] = useState({ servers: [], rows: [] });
  const [users, setUsers] = useState([]);
  const [serviceAccounts, setServiceAccounts] = useState([]);
  const [error, setError] = useState("");

  async function getJson(path) {
    const res = await fetch(`${API}${path}?t=${Date.now()}`);
    if (!res.ok) {
      throw new Error(`${path} returned HTTP ${res.status}`);
    }
    return await res.json();
  }

  async function loadData() {
    try {
      setError("");

      const accessData = await getJson("/api/iam/access-matrix");
      const groupData = await getJson("/api/iam/group-matrix");
      const serviceData = await getJson("/api/iam/service-account-matrix");
      const usersData = await getJson("/api/iam/users");
      const serviceUsersData = await getJson("/api/iam/service-accounts");

      setAccessMatrix(accessData || { servers: [], rows: [] });
      setGroupMatrix(groupData || { servers: [], rows: [] });
      setServiceMatrix(serviceData || { servers: [], rows: [] });
      setUsers(usersData.users || []);
      setServiceAccounts(serviceUsersData.service_accounts || []);
    } catch (err) {
      console.error(err);
      setError(String(err));
    }
  }

  useEffect(() => {
    loadData();
  }, []);

  return (
    <div>
      <h1>IAM</h1>

      {error && (
        <div style={{
          background: "#ffdddd",
          padding: "10px",
          marginBottom: "20px",
          border: "1px solid #cc0000"
        }}>
          {error}
        </div>
      )}

      <MatrixTable
        title="User Access Matrix"
        data={accessMatrix}
        emptyText="No agent-collected IAM user evidence found."
      />

      <MatrixTable
        title="User Group Assignment Matrix"
        data={groupMatrix}
        emptyText="No agent-collected IAM user group evidence found."
      />

      <DetailTable
        title="IAM User Evidence Details"
        rows={users}
        service={false}
      />

      <MatrixTable
        title="Service Account Group Matrix"
        data={serviceMatrix}
        emptyText="No service account evidence found."
      />

      <DetailTable
        title="Service Account Evidence Details"
        rows={serviceAccounts}
        service={true}
      />
    </div>
  );
}
