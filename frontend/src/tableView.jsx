import React, { useEffect, useMemo, useState } from "react";
import { matchesQuery } from "./tableTools";

const PAGE_SIZES = [10, 25, 50, 100];

function normalizeSortValue(value) {
  if (value === null || value === undefined) return "";
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (Array.isArray(value)) return value.join(" ").toLocaleLowerCase();
  if (typeof value === "object") return JSON.stringify(value).toLocaleLowerCase();
  return String(value).toLocaleLowerCase();
}

function compareValues(left, right) {
  const a = normalizeSortValue(left);
  const b = normalizeSortValue(right);

  if (typeof a === "number" && typeof b === "number") return a - b;
  if (typeof a === "boolean" && typeof b === "boolean") return Number(a) - Number(b);
  return String(a).localeCompare(String(b), undefined, {
    numeric: true,
    sensitivity: "base"
  });
}

export function useTableView(rows, query, columns, defaultSort = null) {
  const [sort, setSort] = useState(defaultSort);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  const filteredRows = useMemo(
    () => (rows || []).filter(row => matchesQuery(row, query)),
    [rows, query]
  );

  const sortedRows = useMemo(() => {
    if (!sort?.key) return filteredRows;
    const column = columns.find(item => item.key === sort.key);
    if (!column) return filteredRows;

    const getValue = column.sortValue || (row => row[column.key]);
    const direction = sort.direction === "desc" ? -1 : 1;

    return filteredRows
      .map((row, index) => ({ row, index }))
      .sort((left, right) => {
        const result = compareValues(getValue(left.row), getValue(right.row));
        return result === 0 ? left.index - right.index : result * direction;
      })
      .map(item => item.row);
  }, [filteredRows, sort, columns]);

  const pageCount = Math.max(1, Math.ceil(sortedRows.length / pageSize));
  const safePage = Math.min(page, pageCount);
  const startIndex = (safePage - 1) * pageSize;
  const pagedRows = sortedRows.slice(startIndex, startIndex + pageSize);

  useEffect(() => {
    setPage(1);
  }, [query, pageSize]);

  useEffect(() => {
    if (page > pageCount) setPage(pageCount);
  }, [page, pageCount]);

  function toggleSort(key) {
    setSort(current => {
      if (!current || current.key !== key) return { key, direction: "asc" };
      if (current.direction === "asc") return { key, direction: "desc" };
      return null;
    });
    setPage(1);
  }

  return {
    filteredRows,
    sortedRows,
    pagedRows,
    sort,
    toggleSort,
    page: safePage,
    setPage,
    pageSize,
    setPageSize,
    pageCount,
    startIndex
  };
}

export function SortableHeader({ column, sort, onSort, className = "" }) {
  const sortable = column.sortable !== false && column.key !== "actions";
  const active = sort?.key === column.key;
  const indicator = active ? (sort.direction === "asc" ? "▲" : "▼") : "↕";

  return (
    <th className={className} aria-sort={active ? (sort.direction === "asc" ? "ascending" : "descending") : "none"}>
      {sortable ? (
        <button className="sortable-header" type="button" onClick={() => onSort(column.key)}>
          <span>{column.label}</span>
          <span className={active ? "sort-indicator active" : "sort-indicator"} aria-hidden="true">{indicator}</span>
        </button>
      ) : column.label}
    </th>
  );
}

export function PaginationControls({ page, pageCount, pageSize, setPage, setPageSize, total, startIndex, visibleCount }) {
  if (total === 0) return null;

  const first = startIndex + 1;
  const last = startIndex + visibleCount;

  return (
    <div className="table-pagination" aria-label="Table pagination">
      <span className="muted">Showing {first}–{last} of {total}</span>
      <label>
        Rows
        <select value={pageSize} onChange={event => setPageSize(Number(event.target.value))}>
          {PAGE_SIZES.map(size => <option key={size} value={size}>{size}</option>)}
        </select>
      </label>
      <button className="secondary" type="button" disabled={page <= 1} onClick={() => setPage(1)}>First</button>
      <button className="secondary" type="button" disabled={page <= 1} onClick={() => setPage(value => Math.max(1, value - 1))}>Previous</button>
      <span className="table-page-status">Page {page} of {pageCount}</span>
      <button className="secondary" type="button" disabled={page >= pageCount} onClick={() => setPage(value => Math.min(pageCount, value + 1))}>Next</button>
      <button className="secondary" type="button" disabled={page >= pageCount} onClick={() => setPage(pageCount)}>Last</button>
    </div>
  );
}
