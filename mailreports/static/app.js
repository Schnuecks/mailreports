// SPDX-License-Identifier: AGPL-3.0-or-later
// Filters apply as soon as they change.
document.addEventListener("change", (event) => {
  const el = event.target;
  if (el.matches("[data-autosubmit]") && el.form) el.form.submit();
});
