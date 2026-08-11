// The join form POSTs to /api/login so the site exercises a real API endpoint
// (a useful target for the WAF / GoTestWAF). The response is shown as-is.
document.getElementById("join-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const result = document.getElementById("result");

  const payload = {
    username: form.username.value,
    password: form.password.value,
  };

  try {
    const res = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    result.textContent = "Server response (" + res.status + "):\n" +
      JSON.stringify(data, null, 2);
  } catch (err) {
    result.textContent = "Request failed: " + err;
  }
  result.hidden = false;
});
