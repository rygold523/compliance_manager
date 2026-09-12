export const DISPLAY_TIME_ZONE = "America/New_York";

const ISO_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/;

export function isTimestampValue(value) {
  return typeof value === "string" && ISO_TIMESTAMP.test(value);
}

export function formatDateTime(value, emptyValue = "Never") {
  if (!value) return emptyValue;

  const normalized = (
    typeof value === "string" &&
    ISO_TIMESTAMP.test(value) &&
    !/(?:Z|[+-]\d{2}:?\d{2})$/.test(value)
  ) ? `${value}Z` : value;
  const date = new Date(normalized);
  if (Number.isNaN(date.getTime())) return String(value);

  return new Intl.DateTimeFormat("en-US", {
    timeZone: DISPLAY_TIME_ZONE,
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    timeZoneName: "short"
  }).format(date);
}
