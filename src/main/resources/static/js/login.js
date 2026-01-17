function login() {
  fetch("/auth/user/login", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      username: document.getElementById("username").value,
      password: document.getElementById("password").value,
    }),
  })
    .then((res) => {
      if (!res.ok) throw new Error("Login failed");
      return res.json();
    })
    .then(() => (window.location.href = "/home"))
    .catch(() => {
      document.getElementById("error").innerText = "Invalid credentials";
    });
}
