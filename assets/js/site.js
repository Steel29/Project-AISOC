const navToggle = document.querySelector(".nav-toggle");
const siteNav = document.querySelector(".site-nav");
const page = document.body.dataset.page;

if (siteNav && page) {
  const activeLink = siteNav.querySelector(`[data-nav="${page}"]`);
  if (activeLink) {
    activeLink.classList.add("is-active");
  }
}

if (navToggle && siteNav) {
  navToggle.addEventListener("click", () => {
    const isOpen = siteNav.classList.toggle("is-open");
    navToggle.setAttribute("aria-expanded", String(isOpen));
  });
}

document.querySelectorAll("[data-copy-target]").forEach((button) => {
  button.addEventListener("click", async () => {
    const targetId = button.getAttribute("data-copy-target");
    const source = targetId ? document.getElementById(targetId) : null;

    if (!source) {
      return;
    }

    const copyText = "value" in source ? source.value.trim() : source.textContent.trim();

    try {
      await navigator.clipboard.writeText(copyText);
      setCopiedState(button, "Copied");
    } catch (error) {
      const fallback = document.createElement("textarea");
      fallback.value = copyText;
      fallback.setAttribute("readonly", "");
      fallback.style.position = "absolute";
      fallback.style.left = "-9999px";
      document.body.appendChild(fallback);
      fallback.select();

      try {
        document.execCommand("copy");
        setCopiedState(button, "Copied");
      } catch (fallbackError) {
        setCopiedState(button, "Copy failed", true);
      } finally {
        fallback.remove();
      }
    }
  });
});

function setCopiedState(button, label, failed = false) {
  const previousLabel = button.dataset.defaultLabel || button.textContent;
  button.dataset.defaultLabel = previousLabel;
  button.textContent = label;
  if (!failed) {
    button.classList.add("is-copied");
  }

  window.setTimeout(() => {
    button.textContent = previousLabel;
    button.classList.remove("is-copied");
  }, 1400);
}

const filterChips = document.querySelectorAll(".filter-chip");
const resourceCards = document.querySelectorAll(".resource-card");

if (filterChips.length && resourceCards.length) {
  filterChips.forEach((chip) => {
    chip.addEventListener("click", () => {
      const category = chip.dataset.filter || "all";

      filterChips.forEach((item) => item.classList.remove("is-active"));
      chip.classList.add("is-active");

      resourceCards.forEach((card) => {
        const tags = card.dataset.category || "";
        const show = category === "all" || tags.includes(category);
        card.classList.toggle("is-hidden", !show);
      });
    });
  });
}
