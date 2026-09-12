function scalar(value) {
  if (value === null || value === undefined) return "";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

export function matchesQuery(row, query) {
  const needle = query.trim().toLocaleLowerCase();
  if (!needle) return true;
  return Object.values(row || {}).some(value =>
    scalar(value).toLocaleLowerCase().includes(needle)
  );
}

function csvCell(value) {
  const rendered = scalar(value).replace(/"/g, '""');
  return `"${rendered}"`;
}

export function downloadCsv(filename, columns, rows) {
  const header = columns.map(column => csvCell(column.label)).join(",");
  const body = rows.map(row =>
    columns.map(column => csvCell(
      column.exportValue ? column.exportValue(row) : row[column.key]
    )).join(",")
  );
  const blob = new Blob([[header, ...body].join("\n")], {
    type: "text/csv;charset=utf-8"
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}
