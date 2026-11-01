// Naija Scam Message Checker
// Rule-based: each rule looks for a known scam pattern and adds to the score.
// Everything runs in the browser; the message is never sent anywhere.

const messageBox = document.getElementById("message");
const checkBtn = document.getElementById("check");
const clearBtn = document.getElementById("clear");
const result = document.getElementById("result");
const meterFill = document.getElementById("meter-fill");
const verdict = document.getElementById("verdict");
const summary = document.getElementById("summary");
const flagList = document.getElementById("flags");
const highlighted = document.getElementById("highlighted");

// ---------- Example messages ----------
const SAMPLES = {
  bvn: "Dear Customer, your GTBank account has been restricted due to incomplete BVN. Kindly update your BVN within 24hrs to avoid permanent deactivation. Click: http://gtbank-verify-ng.xyz/update",
  job: "Congratulations! You have been shortlisted for a remote Shell Nigeria job paying N350,000 monthly. Pay a registration fee of N5,000 to confirm your slot. Oya chat this number sharp sharp: wa.me/2348000000000",
  alert: "Acct:******4321 Amt:NGN75,000.00 CR Desc:Transfer. Bro abeg I sent 75k to your account by mistake, please refund it to my Opay 8012345678, my boss go kill me",
  safe: "Your Access Bank OTP is 482913. It expires in 5 minutes. Do not share this code with anyone, including bank staff."
};

// ---------- Reference lists ----------
// Real domains for Nigerian banks and agencies. A link that uses one of these
// names but isn't on the real domain is a strong sign of a fake site.
const OFFICIAL_DOMAINS = {
  gtbank: "gtbank.com",
  gtco: "gtcoplc.com",
  access: "accessbankplc.com",
  firstbank: "firstbanknigeria.com",
  zenith: "zenithbank.com",
  uba: "ubagroup.com",
  opay: "opayweb.com",
  palmpay: "palmpay.com",
  kuda: "kuda.com",
  moniepoint: "moniepoint.com",
  fcmb: "fcmb.com",
  fidelity: "fidelitybank.ng",
  sterling: "sterling.ng",
  wema: "wemabank.com",
  stanbic: "stanbicibtcbank.com",
  nimc: "nimc.gov.ng",
  cbn: "cbn.gov.ng"
};

const SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "cutt.ly", "rb.gy", "is.gd", "shorturl.at", "tiny.cc", "ow.ly"];
const CHEAP_TLDS = [".xyz", ".top", ".click", ".live", ".online", ".site", ".buzz", ".info", ".icu", ".shop"];

// ---------- Rules ----------
// Each rule has: a name, a weight, an explanation, and a regex for the words to highlight.
const RULES = [
  {
    id: "sensitive",
    name: "Asks for your BVN, NIN, OTP, PIN or card details",
    weight: 3,
    why: "No bank or agency will ever ask for these by SMS or WhatsApp. With them, a scammer can empty your account.",
    pattern: /\b(bvn|nin|otp|pin|cvv|password|card number|token|security code)\b/gi,
    // A genuine OTP text tells you NOT to share it, so don't flag that case.
    skipIf: /(do not|don't|never) share/i
  },
  {
    id: "threat",
    name: "Threatens your account or rushes you",
    weight: 2,
    why: "Scammers create panic so you act before you think. Real banks don't block accounts over a text you ignored.",
    pattern: /\b(restricted|blocked|suspended|deactivat\w*|frozen|within \d+\s?(hrs?|hours?|minutes?)|immediately|urgent\w*|final warning|last chance|avoid (permanent )?(deactivation|suspension|blockage))\b/gi
  },
  {
    id: "fee",
    name: "Asks you to pay a fee first",
    weight: 3,
    why: "Real jobs, loans and prizes don't ask you to pay before you receive anything. This is the classic advance-fee scam.",
    pattern: /\b(processing fee|registration fee|activation fee|clearance fee|delivery fee|pay a (small )?fee|send (n|₦)\s?[\d,]+|pay (n|₦)\s?[\d,]+)\b/gi
  },
  {
    id: "prize",
    name: "Too good to be true offer",
    weight: 2,
    why: "Surprise prizes, giveaways, grants and high-paying jobs you never applied for are bait.",
    pattern: /\b(congratulations|you have (won|been selected|been shortlisted)|winner|giveaway|cash prize|free data|grant|loan (has been )?approved|shortlisted)\b/gi
  },
  {
    id: "refund",
    name: "Fake credit alert or 'sent by mistake' story",
    weight: 3,
    why: "A text that looks like a credit alert is easy to fake. Always check your actual balance in your banking app before refunding anyone.",
    pattern: /\b(by mistake|wrong(ly)? (transfer|sent)|refund (it|the money)|reverse (it|the money)|kindly reverse)\b/gi
  },
  {
    id: "pidgin",
    name: "Pidgin pressure to act fast",
    weight: 1,
    why: "Friendly, casual pressure in Pidgin is common in WhatsApp scams that pretend to be someone you know.",
    pattern: /\b(abeg|oya|sharp sharp|quick quick|no dey waste time|my boss go|e go block|do am fast)\b/gi
  },
  {
    id: "contact",
    name: "Pushes you to a phone number or chat",
    weight: 1,
    why: "Moving you to a private chat lets the scammer pressure you away from official channels.",
    pattern: /\b(chat this number|call this number|whatsapp (this|us on)|send to this number|wa\.me\/\d+)/gi
  }
];

// ---------- Link checks ----------
// Matches web addresses (example.com/path) and raw IP addresses (192.168.0.1/path).
const URL_PATTERN = /\b((https?:\/\/)?(([a-z0-9-]+\.)+[a-z]{2,}|\d{1,3}(\.\d{1,3}){3})(:\d+)?(\/[^\s]*)?)/gi;

function checkLink(url) {
  const problems = [];
  const clean = url.replace(/^https?:\/\//i, "").toLowerCase();
  const host = clean.split("/")[0].split(":")[0];

  if (SHORTENERS.some((s) => host === s || host.endsWith("." + s))) {
    problems.push("is a shortened link that hides where it really goes");
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    problems.push("points to a raw IP address instead of a real website");
  }
  if (CHEAP_TLDS.some((tld) => host.endsWith(tld))) {
    problems.push("uses a cheap domain ending that scammers like (" + host.slice(host.lastIndexOf(".")) + ")");
  }
  for (const [brand, real] of Object.entries(OFFICIAL_DOMAINS)) {
    const isReal = host === real || host.endsWith("." + real);
    if (host.includes(brand) && !isReal) {
      problems.push(`uses the name "${brand}" but isn't the real site (${real})`);
      break;
    }
  }
  if (/^http:\/\//i.test(url) && problems.length) {
    problems.push("isn't secure (http, not https)");
  }
  return problems;
}

// ---------- Main check ----------
function escapeHtml(text) {
  return text.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function analyse(text) {
  const flags = [];
  const highlights = []; // [start, end] positions to mark

  for (const rule of RULES) {
    if (rule.skipIf && rule.skipIf.test(text)) continue;
    const matches = [...text.matchAll(rule.pattern)];
    if (matches.length) {
      flags.push({ name: rule.name, why: rule.why, weight: rule.weight, found: [...new Set(matches.map((m) => m[0]))] });
      matches.forEach((m) => highlights.push([m.index, m.index + m[0].length]));
    }
  }

  for (const m of text.matchAll(URL_PATTERN)) {
    const problems = checkLink(m[0]);
    if (problems.length) {
      flags.push({
        name: "Suspicious link",
        why: "This link " + problems.join(", and ") + ". Never enter details on a site you reached from a text.",
        weight: 3,
        found: [m[0]]
      });
      highlights.push([m.index, m.index + m[0].length]);
    }
  }

  const score = flags.reduce((sum, f) => sum + f.weight, 0);
  return { flags, score, highlights };
}

function highlight(text, ranges) {
  // Merge overlapping ranges, then wrap each one in <mark>.
  ranges.sort((a, b) => a[0] - b[0]);
  const merged = [];
  for (const r of ranges) {
    const last = merged[merged.length - 1];
    if (last && r[0] <= last[1]) last[1] = Math.max(last[1], r[1]);
    else merged.push([...r]);
  }
  let html = "";
  let pos = 0;
  for (const [start, end] of merged) {
    html += escapeHtml(text.slice(pos, start)) + "<mark>" + escapeHtml(text.slice(start, end)) + "</mark>";
    pos = end;
  }
  return html + escapeHtml(text.slice(pos));
}

function getLevel(score) {
  if (score === 0) return { label: "No obvious red flags", color: "#46d369", width: 8, note: "That doesn't guarantee it's safe. If in doubt, contact the company through its official app or number." };
  if (score <= 3) return { label: "Be careful", color: "#e3b505", width: 40, note: "There are warning signs. Don't click links or send anything until you've checked with the real company." };
  if (score <= 6) return { label: "Likely a scam", color: "#f26b1d", width: 72, note: "Several classic scam tricks are in this message. Don't reply, click or pay." };
  return { label: "Almost certainly a scam", color: "#e50914", width: 100, note: "This message matches many known scam patterns. Delete it and block the sender." };
}

function runCheck() {
  const text = messageBox.value.trim();
  if (!text) {
    messageBox.focus();
    return;
  }

  const { flags, score, highlights } = analyse(text);
  const level = getLevel(score);

  result.hidden = false;
  meterFill.style.width = level.width + "%";
  meterFill.style.background = level.color;
  verdict.textContent = level.label;
  verdict.style.color = level.color;
  summary.textContent = `${flags.length} red flag${flags.length === 1 ? "" : "s"} found. ${level.note}`;

  flagList.innerHTML = flags.length
    ? flags
        .map(
          (f) => `<li>
            <h3>${escapeHtml(f.name)}</h3>
            <p>${escapeHtml(f.why)}</p>
            <p class="found">Found: ${f.found.map((w) => `<code>${escapeHtml(w)}</code>`).join(" ")}</p>
          </li>`
        )
        .join("")
    : "<li><p>None of the known patterns matched.</p></li>";

  highlighted.innerHTML = highlight(text, highlights);
  result.scrollIntoView({ behavior: "smooth", block: "start" });
}

// ---------- Events ----------
checkBtn.addEventListener("click", runCheck);

clearBtn.addEventListener("click", () => {
  messageBox.value = "";
  result.hidden = true;
  messageBox.focus();
});

document.querySelectorAll(".sample").forEach((btn) => {
  btn.addEventListener("click", () => {
    messageBox.value = SAMPLES[btn.dataset.sample];
    runCheck();
  });
});
