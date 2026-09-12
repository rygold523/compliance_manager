export const API =
  import.meta.env.VITE_API_BASE_URL ||
  `${window.location.protocol}//${window.location.hostname}:8000`;


export async function apiFetch(input, init = {}) {
  const response = await window.fetch(input, {
    ...init,
    credentials: "include"
  });

  if (response.status === 401) {
    window.dispatchEvent(new CustomEvent("auth:unauthorized"));
  }

  return response;
}
