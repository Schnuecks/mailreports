// SPDX-License-Identifier: AGPL-3.0-or-later
// With JavaScript the menu folds into a button on phones (without, it simply wraps).
document.documentElement.classList.add("js");
document.addEventListener("click", (event) => {
  const toggle = event.target.closest(".menu-toggle");
  if (!toggle) return;
  const menu = document.getElementById(toggle.getAttribute("aria-controls"));
  const open = toggle.getAttribute("aria-expanded") !== "true";
  toggle.setAttribute("aria-expanded", String(open));
  menu.classList.toggle("open", open);
});

// Filters apply as soon as they change.
document.addEventListener("change", (event) => {
  const el = event.target;
  if (el.matches("[data-autosubmit]") && el.form) el.form.submit();
});
