// Small progressive enhancements. The app works without JavaScript.
document.addEventListener("submit", function (e) {
  var form = e.target;
  var question = form.getAttribute("data-confirm");
  if (question && !window.confirm(question)) {
    e.preventDefault();
    return;
  }
  var label = form.getAttribute("data-busy");
  if (!label) return;
  var btn = form.querySelector('button[type="submit"]');
  if (btn) {
    btn.disabled = true;
    btn.textContent = label;
  }
});
document.addEventListener("DOMContentLoaded", function () {
  document.querySelectorAll(".bar-fill[data-w]").forEach(function (el) {
    var w = parseInt(el.getAttribute("data-w"), 10);
    if (!isNaN(w)) el.style.width = Math.max(0, Math.min(100, w)) + "%";
  });
});
