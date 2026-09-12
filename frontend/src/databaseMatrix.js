function uniqueSorted(values) {
  return [...new Set(values.filter(Boolean))].sort((a, b) =>
    String(a).localeCompare(String(b))
  );
}

function databaseServerKey(source) {
  return source.source_key || source.key || source.id || source.name;
}

function databaseServerName(source) {
  return source.source_name || source.name || databaseServerKey(source);
}

export function buildDatabaseUserMatrix(accounts, sources) {
  const serverMap = new Map();

  (sources || []).forEach(source => {
    const key = databaseServerKey(source);
    if (key) serverMap.set(key, databaseServerName(source));
  });

  (accounts || []).forEach(account => {
    const key = account.source_key || account.source_name;
    if (key && !serverMap.has(key)) {
      serverMap.set(key, account.source_name || key);
    }
  });

  const servers = [...serverMap.entries()]
    .map(([key, name]) => ({ key, name }))
    .sort((a, b) => a.name.localeCompare(b.name));
  const users = new Map();

  (accounts || []).forEach(account => {
    const username = account.username;
    const sourceKey = account.source_key || account.source_name;
    if (!username || !sourceKey) return;

    if (!users.has(username)) {
      users.set(username, { username, servers: {} });
    }

    const user = users.get(username);
    const existing = user.servers[sourceKey] || {
      databases: [],
      roles: [],
      privileges: [],
      lastSeenAt: null
    };

    const accessibleDatabases = (account.database_privileges || [])
      .filter(item => item.connect || item.create || item.temp)
      .map(item => item.database);
    const privileges = [];

    if (account.superuser) privileges.push("Superuser");
    if (account.create_role) privileges.push("Create role");
    if (account.create_database) privileges.push("Create database");
    if (account.replication) privileges.push("Replication");
    if (account.bypass_rls) privileges.push("Bypass RLS");

    existing.databases = uniqueSorted([
      ...existing.databases,
      ...accessibleDatabases
    ]);
    existing.roles = uniqueSorted([
      ...existing.roles,
      ...(account.roles || [])
    ]);
    existing.privileges = uniqueSorted([
      ...existing.privileges,
      ...privileges
    ]);

    if (
      account.last_seen_at &&
      (!existing.lastSeenAt || new Date(account.last_seen_at) > new Date(existing.lastSeenAt))
    ) {
      existing.lastSeenAt = account.last_seen_at;
    }

    user.servers[sourceKey] = existing;
  });

  return {
    servers,
    users: [...users.values()].sort((a, b) =>
      a.username.localeCompare(b.username)
    )
  };
}
