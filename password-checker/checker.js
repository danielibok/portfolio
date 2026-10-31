// Password strength checker.
// Everything happens in the browser; the password is never sent anywhere.

const input = document.getElementById("password");
const toggle = document.getElementById("toggle");
const meterFill = document.getElementById("meter-fill");
const verdict = document.getElementById("verdict");
const crackTime = document.getElementById("crack-time");
const ruleItems = document.querySelectorAll("#rules li");

// A short list of passwords that show up at the top of every breach list.
const COMMON = [
  "password", "123456", "12345678", "123456789", "qwerty", "abc123",
  "111111", "letmein", "welcome", "monkey", "dragon", "football",
  "iloveyou", "admin", "login", "princess", "sunshine", "master",
  "passw0rd", "password1", "qwerty123", "1q2w3e4r", "000000", "superman"
];

// Runs of characters attackers try early.
const SEQUENCES = ["abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop", "asdfghjkl", "zxcvbnm"];

// Guesses per second for an offline attack with a modern GPU.
const GUESSES_PER_SECOND = 1e10;

function hasSequence(password) {
  const lower = password.toLowerCase();
  return SEQUENCES.some((seq) => {
    for (let i = 0; i <= seq.length - 3; i++) {
      const run = seq.slice(i, i + 3);
      const reversed = run.split("").reverse().join("");
      if (lower.includes(run) || lower.includes(reversed)) return true;
    }
    return false;
  });
}

// "summer2024", "Daniel1!" and similar: a word with a few numbers or symbols tacked on.
function isWordPlusNumber(password) {
  return /^[A-Za-z]+[0-9!@#$%?]{1,4}$/.test(password);
}

function isCommon(password) {
  // Strip trailing numbers and symbols so "password123!" still counts as common.
  const base = password.toLowerCase().replace(/[^a-z]+$/, "");
  return COMMON.includes(password.toLowerCase()) || COMMON.includes(base);
}

function checkRules(password) {
  return {
    length: password.length >= 12,
    lower: /[a-z]/.test(password),
    upper: /[A-Z]/.test(password),
    number: /[0-9]/.test(password),
    symbol: /[^A-Za-z0-9]/.test(password),
    common: !isCommon(password),
    pattern: !/(.)\1\1/.test(password) && !hasSequence(password) && !isWordPlusNumber(password)
  };
}

// Entropy in bits = length x log2(size of the character pool).
function entropyBits(password, rules) {
  let pool = 0;
  if (rules.lower) pool += 26;
  if (rules.upper) pool += 26;
  if (rules.number) pool += 10;
  if (rules.symbol) pool += 33;

  let bits = password.length * Math.log2(pool || 1);

  // Attackers try common passwords and patterns first, so cut the score hard.
  if (!rules.common) bits = Math.min(bits, 10);
  if (!rules.pattern) bits *= 0.6;
  return bits;
}

function formatTime(seconds) {
  const units = [
    ["year", 31536000],
    ["day", 86400],
    ["hour", 3600],
    ["minute", 60],
    ["second", 1]
  ];
  if (seconds < 1) return "instantly";
  if (seconds > 31536000 * 1e6) return "over a million years";
  for (const [name, size] of units) {
    if (seconds >= size) {
      const value = Math.floor(seconds / size);
      return `about ${value.toLocaleString()} ${name}${value === 1 ? "" : "s"}`;
    }
  }
}

function getLevel(bits) {
  if (bits < 28) return { label: "Very weak", color: "#e50914", width: 15 };
  if (bits < 40) return { label: "Weak", color: "#f26b1d", width: 35 };
  if (bits < 60) return { label: "Okay", color: "#e3b505", width: 60 };
  if (bits < 80) return { label: "Strong", color: "#46d369", width: 82 };
  return { label: "Very strong", color: "#2fbf71", width: 100 };
}

function update() {
  const password = input.value;

  if (!password) {
    meterFill.style.width = "0";
    verdict.textContent = "Start typing to check a password.";
    crackTime.textContent = "";
    ruleItems.forEach((li) => li.classList.remove("pass", "fail"));
    return;
  }

  const rules = checkRules(password);
  const bits = entropyBits(password, rules);
  const level = getLevel(bits);

  ruleItems.forEach((li) => {
    const passed = rules[li.dataset.rule];
    li.classList.toggle("pass", passed);
    li.classList.toggle("fail", !passed);
  });

  meterFill.style.width = level.width + "%";
  meterFill.style.background = level.color;
  verdict.textContent = level.label;
  verdict.style.color = level.color;

  // On average an attacker finds the password after trying half the possibilities.
  const seconds = Math.pow(2, bits) / 2 / GUESSES_PER_SECOND;
  crackTime.textContent = `Estimated time to crack: ${formatTime(seconds)}`;
}

toggle.addEventListener("click", () => {
  const hidden = input.type === "password";
  input.type = hidden ? "text" : "password";
  toggle.textContent = hidden ? "Hide" : "Show";
});

input.addEventListener("input", update);
