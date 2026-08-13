import { useEffect, useState } from "react";
import { register, login, me, logout, getToken } from "../auth.js";

// A real (if deliberately unhardened) account page: register and log in against the
// Flask API, which mints a signed bearer token. Once logged in it shows the token and
// where it lives - localStorage AND a JS-readable `token` cookie - because that is what
// the reflected-XSS demo (/api/sink/xss) steals. The echoed values are rendered as React
// text children, so they are escaped here; only the /api/sink/xss endpoint is unescaped.

export default function Account() {
  const [user, setUser] = useState(null);
  const [token, setTok] = useState("");
  const [mode, setMode] = useState("login"); // "login" | "register"
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  // On load, ask the server who this token belongs to. A stolen token replayed here is
  // exactly how an attacker would confirm account takeover.
  useEffect(() => {
    (async () => {
      const res = await me();
      if (res.ok) {
        setUser(res.user);
        setTok(getToken());
      }
    })();
  }, []);

  async function onSubmit(e) {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      if (mode === "register") {
        const reg = await register(username, password);
        if (!reg.ok) return setError(reg.error || "registration failed");
      }
      const res = await login(username, password);
      if (!res.ok) return setError(res.error || "login failed");
      setUser(res.user);
      setTok(res.token);
      setPassword("");
    } finally {
      setBusy(false);
    }
  }

  async function onLogout() {
    await logout();
    setUser(null);
    setTok("");
    setUsername("");
  }

  if (user) {
    return (
      <>
        <section className="section page-head">
          <p className="eyebrow">Signed in</p>
          <h1>Welcome back, {user.username}</h1>
          <p className="prose">
            Role <strong>{user.role}</strong> · {user.chips} chips. This session is a bearer
            token — steal it and you are this account.
          </p>
        </section>

        <section className="section">
          <div className="panel">
            <h3>Your session token</h3>
            <pre>{token}</pre>
            <p className="prose">
              It lives in <code>localStorage["fnp_token"]</code> <em>and</em> in a JS-readable{" "}
              <code>token</code> cookie, so any script running on this origin can read both.
              A reflected-XSS payload at <code>/api/sink/xss</code> that reads{" "}
              <code>document.cookie</code> or <code>localStorage</code> exfiltrates exactly
              this — then replays it against <code>/api/me</code> as you. The parallel{" "}
              <code>token_httponly</code> cookie is hidden from JavaScript: that is the fix.
            </p>
          </div>
          <button type="button" className="btn" onClick={onLogout}>
            Log out
          </button>
        </section>
      </>
    );
  }

  return (
    <>
      <section className="section page-head">
        <p className="eyebrow">Members</p>
        <h1>{mode === "register" ? "Create an account" : "Log in"}</h1>
        <p className="prose">
          A real account with a hashed password and a bearer-token session — the thing the
          XSS demo actually steals. Do not use a real password; this is a test origin.
        </p>
      </section>

      <section className="section">
        <form className="note-form" onSubmit={onSubmit}>
          <input
            type="text"
            name="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="Username"
            aria-label="Username"
            autoComplete="username"
          />
          <input
            type="password"
            name="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Password"
            aria-label="Password"
            autoComplete={mode === "register" ? "new-password" : "current-password"}
          />
          <button type="submit" className="btn" disabled={busy}>
            {busy ? "…" : mode === "register" ? "Register" : "Log in"}
          </button>
        </form>
        {error && <p className="echo-error">{error}</p>}

        <p className="prose">
          {mode === "register" ? "Already have an account? " : "No account yet? "}
          <a
            href="#"
            onClick={(e) => {
              e.preventDefault();
              setError("");
              setMode(mode === "register" ? "login" : "register");
            }}
          >
            {mode === "register" ? "Log in" : "Register"}
          </a>
        </p>
      </section>
    </>
  );
}
