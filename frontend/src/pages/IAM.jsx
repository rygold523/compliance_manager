import React, { useEffect, useState } from "react";

function MatrixTable({ title, data }) {
  const servers = data?.servers || [];
  const rows = data?.rows || [];

  return (
    <div className="bg-white rounded shadow p-4 mb-6 overflow-auto">
      <h2 className="text-xl font-semibold mb-3">{title}</h2>
      <table className="min-w-full border border-gray-300 text-sm">
        <thead>
          <tr className="bg-gray-100">
            <th className="border px-3 py-2 text-left sticky left-0 bg-gray-100">UserName</th>
            {servers.map((server) => (
              <th key={server} className="border px-3 py-2 text-left whitespace-nowrap">{server}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.username}>
              <td className="border px-3 py-2 font-medium sticky left-0 bg-white">{row.username}</td>
              {servers.map((server) => (
                <td key={server} className="border px-3 py-2 whitespace-pre-wrap">
                  {row[server] || ""}
                </td>
              ))}
            </tr>
          ))}
          {rows.length === 0 && (
            <tr>
              <td className="border px-3 py-2" colSpan={servers.length + 1}>
                No IAM evidence found. Run the iam_users collector first.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

export default function IAM() {
  const [accessMatrix, setAccessMatrix] = useState({ servers: [], rows: [] });
  const [groupMatrix, setGroupMatrix] = useState({ servers: [], rows: [] });
  const [users, setUsers] = useState([]);

  useEffect(() => {
    fetch("/api/iam/access-matrix").then(r => r.json()).then(setAccessMatrix).catch(() => {});
    fetch("/api/iam/group-matrix").then(r => r.json()).then(setGroupMatrix).catch(() => {});
    fetch("/api/iam/users").then(r => r.json()).then(d => setUsers(d.users || [])).catch(() => {});
  }, []);

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-4">IAM</h1>
      <MatrixTable title="User Access Matrix" data={accessMatrix} />
      <MatrixTable title="User Group Assignment Matrix" data={groupMatrix} />

      <div className="bg-white rounded shadow p-4 overflow-auto">
        <h2 className="text-xl font-semibold mb-3">IAM Evidence Details</h2>
        <table className="min-w-full border border-gray-300 text-sm">
          <thead>
            <tr className="bg-gray-100">
              <th className="border px-3 py-2 text-left">Server</th>
              <th className="border px-3 py-2 text-left">User</th>
              <th className="border px-3 py-2 text-left">UID</th>
              <th className="border px-3 py-2 text-left">Shell</th>
              <th className="border px-3 py-2 text-left">Access</th>
              <th className="border px-3 py-2 text-left">Groups</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u, idx) => (
              <tr key={`${u.asset_id}-${u.username}-${idx}`}>
                <td className="border px-3 py-2">{u.asset_id}</td>
                <td className="border px-3 py-2">{u.username}</td>
                <td className="border px-3 py-2">{u.uid}</td>
                <td className="border px-3 py-2">{u.shell}</td>
                <td className="border px-3 py-2">{(u.access || []).join(", ")}</td>
                <td className="border px-3 py-2">{(u.groups || []).join(", ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
