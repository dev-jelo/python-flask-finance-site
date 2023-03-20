const btn = document.querySelector(".toggle");
const theme = document.querySelector("#theme");

if (sessionStorage["mode"] === "dark") {
    theme.href = "/static/dark-theme.css";
    btn.innerHTML = "Light Mode";
} else {
    theme.href = "/static/light-theme.css";
};

btn.addEventListener("click", function() {
    if (theme.getAttribute("href") === "/static/light-theme.css") {
        theme.href = "/static/dark-theme.css";
        btn.innerHTML = "Light Mode"
        sessionStorage["mode"] = "dark";
    } else {
        theme.href = "/static/light-theme.css";
        btn.innerHTML = "Dark Mode"
        sessionStorage.removeItem("mode");
    }
});

