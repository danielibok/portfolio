// Mobile menu, header background on scroll, and screenshot lightbox.

// 1. Mobile menu toggle
const toggle = document.querySelector(".nav-toggle");
const links = document.querySelector(".nav-links");

if (toggle && links) {
  toggle.addEventListener("click", () => {
    const isOpen = links.classList.toggle("open");
    toggle.setAttribute("aria-expanded", isOpen);
  });

  // Close the menu after picking a link
  links.querySelectorAll("a").forEach((link) => {
    link.addEventListener("click", () => {
      links.classList.remove("open");
      toggle.setAttribute("aria-expanded", "false");
    });
  });
}

// 2. Solid header once the page is scrolled
const header = document.querySelector(".site-header");

function updateHeader() {
  header.classList.toggle("scrolled", window.scrollY > 40);
}

window.addEventListener("scroll", updateHeader);
updateHeader();

// 3. Lightbox for screenshots on the project page
const lightbox = document.querySelector(".lightbox");

if (lightbox) {
  const lightboxImg = lightbox.querySelector("img");
  const closeBtn = lightbox.querySelector(".lightbox-close");

  document.querySelectorAll(".gallery button").forEach((btn) => {
    btn.addEventListener("click", () => {
      const img = btn.querySelector("img");
      lightboxImg.src = img.src;
      lightboxImg.alt = img.alt;
      lightbox.classList.add("open");
      closeBtn.focus();
    });
  });

  function closeLightbox() {
    lightbox.classList.remove("open");
  }

  closeBtn.addEventListener("click", closeLightbox);
  lightbox.addEventListener("click", (e) => {
    if (e.target === lightbox) closeLightbox();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeLightbox();
  });
}
