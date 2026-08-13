// Client side of the account system. The bearer token is kept in localStorage (and the
// server also drops it in a JS-readable `token` cookie), so BOTH are reachable by an XSS
// payload on this origin - which is exactly the point of the reflected-XSS demo. A real
// app would keep the session in an HttpOnly cookie and never in localStorage.

const TOKEN_KEY = "fnp_token";

export function getToken() {
  return localStorage.getItem(TOKEN_KEY) || "";
}
export function setToken(token) {
  localStorage.setItem(TOKEN_KEY, token);
}
export function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}
export function authHeader() {
  const token = getToken();
  return token ? { Authorization: "Bearer " + token } : {};
}

async function postJSON(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeader() },
    body: JSON.stringify(body),
  });
  // The origin always answers 200 with an {ok} body; a non-JSON reply means a WAF block
  // page got in the way, so surface that rather than throwing.
  try {
    return await res.json();
  } catch {
    return { ok: false, error: `unexpected ${res.status} response (WAF block page?)` };
  }
}

export function register(username, password) {
  return postJSON("/api/register", { username, password });
}

export async function login(username, password) {
  const result = await postJSON("/api/login", { username, password });
  if (result.ok && result.token) setToken(result.token);
  return result;
}

export async function me() {
  const res = await fetch("/api/me", { headers: authHeader() });
  try {
    return await res.json();
  } catch {
    return { ok: false, error: "could not read session" };
  }
}

export async function logout() {
  try {
    await fetch("/api/logout", { method: "POST", headers: authHeader() });
  } finally {
    clearToken();
  }
}
