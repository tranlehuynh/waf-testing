import { useState } from "react";

// This page is the site's request-testing surface: the search sends the query
// in the URL (GET /api/rules?q=...) and the note box sends it in the body
// (POST /api/notes). The origin echoes both back with a 200, so whatever you
// see here that is NOT a 200 was stopped by the WAF in front.
//
// The echoed text is rendered as a React text child, which escapes it. Never
// switch these to dangerouslySetInnerHTML.

const RULES = [
  {
    title: "Blinds & antes",
    body: "Small blind one chip, big blind two. No antes - we are not monsters.",
  },
  {
    title: "String bets",
    body: "Say the number or push it all at once. Reaching back for more chips does not count, and you will be called on it.",
  },
  {
    title: "Re-buys",
    body: "One re-buy before the halfway mark, same twenty. After that you are a spectator with opinions.",
  },
  {
    title: "Misdeals",
    body: "A card flipped during the deal means a reshuffle. Flipped after the deal, it becomes the burn and we move on.",
  },
  {
    title: "Phones",
    body: "Face-down on the table. If you have to take it, fold first.",
  },
  {
    title: "The kitchen",
    body: "Open to everyone. Label anything you want back, and whoever finishes the crisps buys next week's.",
  },
];

const SEED_NOTES = [
  { text: "bringing the good whiskey, don't start without me", who: "tuan", when: "wed" },
  { text: "aces cracked twice last week. brutal. back for more.", who: "mai", when: "thu" },
  { text: "i still have the deck from last time — sorry", who: "linh", when: "fri" },
];

/** Status line + collapsible raw response, shared by both forms. */
function Echo({ meta }) {
  if (!meta) return null;
  if (meta.error) {
    return <p className="echo-error">Request failed: {meta.error}</p>;
  }
  const ok = meta.status === 200;
  return (
    <details className="echo">
      <summary>
        <span className={ok ? "pill pill-ok" : "pill pill-blocked"}>{meta.status}</span>
        <span className="echo-ms">{meta.ms} ms</span>
        <span className="echo-hint">
          {ok ? "origin echoed the request" : "stopped before the origin"}
        </span>
      </summary>
      <pre>{meta.body.slice(0, 4000)}</pre>
    </details>
  );
}

export default function Rules() {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState(RULES);
  const [searchMeta, setSearchMeta] = useState(null);
  const [note, setNote] = useState("");
  const [notes, setNotes] = useState(SEED_NOTES);
  const [noteMeta, setNoteMeta] = useState(null);
  const [sending, setSending] = useState(false);

  // res.text() rather than res.json(): a WAF block page is usually HTML, and
  // json() would throw before we could show the status code.
  async function send(url, options) {
    const started = performance.now();
    try {
      const res = await fetch(url, options);
      return {
        status: res.status,
        ms: Math.round(performance.now() - started),
        body: await res.text(),
      };
    } catch (err) {
      return { error: String(err) };
    }
  }

  async function onSearch(e) {
    e.preventDefault();
    const q = query.trim();
    setSearchMeta(await send(`/api/rules?q=${encodeURIComponent(q)}`));

    const needle = q.toLowerCase();
    setResults(
      needle
        ? RULES.filter((r) => `${r.title} ${r.body}`.toLowerCase().includes(needle))
        : RULES,
    );
  }

  async function onPin(e) {
    e.preventDefault();
    const text = note.trim();
    if (!text) return;

    setSending(true);
    const meta = await send("/api/notes", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ note: text }),
    });
    setSending(false);
    setNoteMeta(meta);

    if (meta.status === 200) {
      setNotes([{ text, who: "you", when: "just now" }, ...notes]);
      setNote("");
    }
  }

  return (
    <>
      <section className="section page-head">
        <p className="eyebrow">The short version</p>
        <h1>House rules</h1>
        <p className="prose">
          Six of them, and none are strict. Search if you are looking for
          something specific, or read the lot — it takes a minute.
        </p>
      </section>

      <section className="section">
        <form className="search" onSubmit={onSearch}>
          <input
            type="search"
            name="q"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search the house rules…"
            aria-label="Search the house rules"
            autoComplete="off"
          />
          <button type="submit" className="btn">
            Search
          </button>
        </form>
        <Echo meta={searchMeta} />

        <div className="panel-grid rules-grid">
          {results.map((r) => (
            <article className="panel" key={r.title}>
              <h3>{r.title}</h3>
              <p>{r.body}</p>
            </article>
          ))}
        </div>
        {results.length === 0 && (
          <p className="empty">
            Nothing matches that. It is probably fine — ask at the table.
          </p>
        )}
      </section>

      <section className="section">
        <h2>Leave a note for the table</h2>
        <form className="note-form" onSubmit={onPin}>
          <input
            type="text"
            name="note"
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="Bringing the good whiskey…"
            aria-label="Leave a note for the table"
            autoComplete="off"
          />
          <button type="submit" className="btn" disabled={sending}>
            {sending ? "Pinning…" : "Pin it"}
          </button>
        </form>
        <Echo meta={noteMeta} />

        <ul className="notes">
          {notes.map((n, i) => (
            <li key={i}>
              <p>{n.text}</p>
              <span className="note-by">
                {n.who} · {n.when}
              </span>
            </li>
          ))}
        </ul>
      </section>
    </>
  );
}
