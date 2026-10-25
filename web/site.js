(() => {
  const body = document.body;
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const km = () => document.documentElement.lang === "km";
  const t = (p) => (km() ? p.km : p.en);
  const $ = (id) => document.getElementById(id);

  // The bot's real replies (src/verdict.rs), first lines only.
  const DEMO = [
    {
      out: { fwd: "ABA Bank Support", text: { km: "សួស្តីបង ខ្ញុំមកពីធនាគារ ABA។ គណនីរបស់បងនឹងត្រូវបង្កកក្នុងរយៈពេល ២៤ម៉ោង។ សូមផ្ញើលេខកូដ OTP ដែលបងទើបទទួលបាន មកខ្ញុំភ្លាមៗ។", en: "Hi, I'm from ABA Bank. Your account will be frozen within 24 hours. Send me the OTP code you just received right away." } },
      reply: { km: ["<strong>🔴 ហានិភ័យខ្ពស់</strong>", "សារនេះមានការទាមទារលេខកូដ OTP ឬលេខសម្ងាត់។ ធនាគារ និងក្រុមហ៊ុនផ្លូវការ ដាច់ខាតមិនដែលសុំលេខទាំងនេះឡើយ។", "👉 កុំឆ្លើយតប កុំប្រាប់លេខកូដ ហើយកុំផ្ទេរលុយ។"], en: ["<strong>🔴 High risk</strong>", "This message asks for an OTP code or password. Real banks and companies never ask for these.", "👉 Don't reply, don't share any code, and don't send money."] },
    },
    {
      out: { link: "https://aba-verify-login.top/account" },
      reply: { km: ["<strong>🔴 ហានិភ័យខ្ពស់</strong>", "ឈ្មោះគេហទំព័រនេះស្រដៀង ABA តែមិនមែនគេហទំព័រផ្លូវការទេ។", "👉 កុំបើកតំណនេះ ហើយកុំបញ្ចូលព័ត៌មានអ្វីទាំងអស់។"], en: ["<strong>🔴 High risk</strong>", "This site's name looks like ABA, but it isn't the official site.", "👉 Don't open this link or enter anything on it."] },
    },
    {
      out: { file: "ABA Mobile.apk", size: "6.2 MB" },
      reply: { km: ["<strong>🔴 ហានិភ័យខ្ពស់</strong>", "កម្មវិធីនេះប្រើឈ្មោះ ABA។ ធនាគារមិនដែលផ្ញើកម្មវិធីតាម Telegram ទេ។", "👉 កុំបើក ឬដំឡើងឯកសារនេះ ហើយលុបវាចោល។", "🔓 អាច៖ អាន SMS · គ្រប់គ្រងអេក្រង់"], en: ["<strong>🔴 High risk</strong>", "This app uses the name ABA. Banks never send apps over Telegram.", "👉 Don't open or install this file. Delete it.", "🔓 Can: read SMS · control the screen"] },
    },
    {
      out: { fwd: "Lucky Job Center", text: { km: "ជ្រើសរើសបុគ្គលិកវាយអក្សរ និងឆាត ប្រាក់ខែ $1000 នៅប៉ោយប៉ែត។ មិនត្រូវការបទពិសោធន៍។ ទាក់ទង 097 555 1234", en: "Hiring typing and chat staff, salary $1000, in Poipet. No experience needed. Call 097 555 1234" } },
      reply: { km: ["<strong>🟠 គួរឱ្យសង្ស័យ</strong>", "សារនេះសន្យាការងារស្រួលៗ តែបានលុយច្រើនពេក ដូចជាចុចឡាយ ឬវាយអក្សរ។", "👉 សូមផ្ទៀងផ្ទាត់តាមលេខ ឬកម្មវិធីផ្លូវការសិន មុនពេលធ្វើតាមសារនេះ។"], en: ["<strong>🟠 Suspicious</strong>", "This message promises easy work for too much money, like clicking likes or typing.", "👉 Check through an official number or app before you do what it asks."] },
    },
    {
      out: { voice: "0:12" },
      reply: { km: ["<strong>🔴 ហានិភ័យខ្ពស់</strong>", "សារនេះមានការទាមទារលេខកូដ OTP ឬលេខសម្ងាត់។ ធនាគារ និងក្រុមហ៊ុនផ្លូវការ ដាច់ខាតមិនដែលសុំលេខទាំងនេះឡើយ។", "👉 កុំឆ្លើយតប កុំប្រាប់លេខកូដ ហើយកុំផ្ទេរលុយ។", "📞 ចង់ផ្ទៀងផ្ទាត់ សូមទាក់ទង Wing៖ ហតឡាញ 023 999 989 (ពីគេហទំព័រផ្លូវការរបស់ Wing)។"], en: ["<strong>🔴 High risk</strong>", "This message asks for an OTP code or password. Real banks and companies never ask for these.", "👉 Don't reply, don't share any code, and don't send money.", "📞 To check, contact Wing: hotline 023 999 989 (from Wing's own website)."] },
    },
  ];
  const WAVE = [8, 14, 20, 12, 24, 16, 9, 18, 26, 14, 10, 22, 17, 8, 13, 21, 11, 7].map((h) => `<b style="height:${h}px"></b>`).join("");

  // ---------- Giant title fitted to its real ink, so Khmer vowels never clip ----------

  const ctx = document.createElement("canvas").getContext("2d");
  const ink = (el, size) => {
    const cs = getComputedStyle(el);
    ctx.font = `${cs.fontWeight} ${size}px ${cs.fontFamily}`;
    if ("fontStretch" in ctx) ctx.fontStretch = cs.fontStretch === "75%" ? "condensed" : "normal";
    return ctx.measureText(cs.textTransform === "uppercase" ? el.textContent.toUpperCase() : el.textContent);
  };
  const fit = () => {
    document.querySelectorAll(".mega").forEach((m) => {
      const el = m.querySelector(".fit");
      const p = ink(el, 100);
      const wide = (100 * m.clientWidth) / (p.actualBoundingBoxLeft + p.actualBoundingBoxRight);
      const tall = (innerHeight * Number(m.dataset.cap) * 100) / (p.actualBoundingBoxAscent + p.actualBoundingBoxDescent);
      const size = innerWidth <= 720 ? wide : Math.min(wide, tall);
      const g = ink(el, size);
      const pad = size * 0.03;
      const line = g.actualBoundingBoxAscent + g.actualBoundingBoxDescent + pad * 2;
      const baseline = (line - (g.fontBoundingBoxAscent + g.fontBoundingBoxDescent)) / 2 + g.fontBoundingBoxAscent;
      el.style.fontSize = size + "px";
      el.style.lineHeight = line + "px";
      el.style.top = pad + g.actualBoundingBoxAscent - baseline + "px";
      el.style.width = g.actualBoundingBoxLeft + g.actualBoundingBoxRight + "px";
      el.style.textIndent = g.actualBoundingBoxLeft + "px";
      m.querySelector(".mask").style.height = line + "px";
      if (m.id === "foot-mega") m.style.height = line * 0.72 + "px";
    });
  };

  // ---------- Reveals ----------

  const reveal = new IntersectionObserver((entries) => {
    entries.forEach((e) => {
      if (e.isIntersecting) { e.target.classList.add("seen"); reveal.unobserve(e.target); }
    });
  }, { threshold: 0.15, rootMargin: "0px 0px -6% 0px" });
  const watch = (root) => root.querySelectorAll(".rv, .mask:not(.mega .mask), .line-top:not(.hero-foot), #foot-mega").forEach((el) => reveal.observe(el));

  // Lines from your message, into CheckSen, out to each service, with dots flowing along them.
  const wire = () => {
    const flow = $("flow"), svg = $("wires");
    if (!flow || matchMedia("(max-width: 1080px)").matches) { if (svg) svg.innerHTML = ""; return; }
    const box = flow.getBoundingClientRect();
    const at = (el, side) => {
      const r = el.getBoundingClientRect();
      return [(side === "r" ? r.right : r.left) - box.left, r.top + r.height / 2 - box.top];
    };
    const src = flow.querySelector('[data-wire="src"]'), core = flow.querySelector('[data-wire="core"]');
    const curve = ([x1, y1], [x2, y2]) => { const m = (x1 + x2) / 2; return `M${x1} ${y1}C${m} ${y1} ${m} ${y2} ${x2} ${y2}`; };
    const paths = [curve(at(src, "r"), at(core, "l")), ...[...flow.querySelectorAll('[data-wire="dest"]')].map((d) => curve(at(core, "r"), at(d, "l")))];
    svg.setAttribute("width", box.width);
    svg.setAttribute("height", box.height);
    svg.innerHTML = paths.map((d, i) => `<path d="${d}"/>` + (reduce ? "" : `<circle r="3"><animateMotion dur="${2.4 + i * 0.3}s" begin="${i === 0 ? 0 : 0.8 + i * 0.25}s" repeatCount="indefinite" path="${d}"/></circle>`)).join("");
  };
  document.addEventListener("click", (e) => {
    const q = $("qr-btn");
    q.setAttribute("aria-expanded", e.target.closest("#qr-btn") ? q.getAttribute("aria-expanded") !== "true" : false);
  });
  document.addEventListener("click", (e) => {
    const b = e.target.closest("#more");
    if (!b) return;
    const open = b.getAttribute("aria-expanded") !== "true";
    b.setAttribute("aria-expanded", open);
    $("fine").classList.toggle("open", open);
  });

  // ---------- Telegram demo ----------

  const thread = $("thread"), status = $("status"), picks = $("picks");
  const demo = $("demo"), notes = $("notes"), leaders = $("leaders");

  // Each note sits level with the part of the reply it explains, joined by a thin line.
  const layoutNotes = () => {
    const bub = thread.querySelector(".bub.in");
    if (!bub) return;
    if (matchMedia("(max-width: 1080px)").matches) { leaders.innerHTML = ""; return; }
    const box = demo.getBoundingClientRect();
    const nb = notes.getBoundingClientRect();
    const chat = demo.querySelector(".tg").getBoundingClientRect();
    const br = bub.getBoundingClientRect();
    const ps = bub.querySelectorAll("p");
    const targets = { sent: thread.querySelector(".bub.out"), level: ps[0], why: ps[1], act: ps[2], more: bub.querySelector(".quote"), report: thread.querySelector(".kb") };
    const ex = nb.right - box.left - 52;
    const items = [...notes.children].map((li) => {
      const r = targets[li.dataset.k].getBoundingClientRect();
      return { li, sy: r.top + r.height / 2 - box.top, sx: (li.dataset.k === "report" || li.dataset.k === "sent" ? r.left : br.left) - box.left };
    });
    // Spread the labels evenly around the parts they point to, so lines never cross or bunch up.
    const first = items[0].sy, last = items[items.length - 1].sy;
    const gap = Math.max(52, (last - first) / (items.length - 1));
    const start = (first + last) / 2 - (gap * (items.length - 1)) / 2;
    let svg = "";
    items.forEach(({ li, sy, sx }, i) => {
      const ey = start + gap * i;
      li.style.top = ey - (nb.top - box.top) - li.offsetHeight / 2 + "px";
      const bend = (sx - ex) * 0.5;
      const d = `M${sx} ${sy}C${sx - bend} ${sy} ${ex + bend} ${ey} ${ex} ${ey}`;
      svg += `<path pathLength="1" style="--len:1;--dl:${i * 0.07}s" d="${d}"/><circle style="--dl:${i * 0.07}s" cx="${sx}" cy="${sy}" r="3.5"/>`;
    });
    notes.style.minHeight = "";
    leaders.setAttribute("width", box.width);
    leaders.setAttribute("height", box.height);
    leaders.innerHTML = svg;
  };
  notes.addEventListener("mouseover", (e) => {
    const li = e.target.closest("li");
    thread.querySelectorAll(".hl").forEach((el) => el.classList.remove("hl"));
    if (!li) return;
    const bub = thread.querySelector(".bub.in");
    const ps = bub ? bub.querySelectorAll("p") : [];
    const el = { sent: thread.querySelector(".bub.out"), level: ps[0], why: ps[1], act: ps[2], more: bub && bub.querySelector(".quote"), report: thread.querySelector(".kb") }[li.dataset.k];
    if (el) el.classList.add("hl");
  });
  notes.addEventListener("mouseleave", () => thread.querySelectorAll(".hl").forEach((el) => el.classList.remove("hl")));
  let current = 0, run = 0, autoplay = true;
  const wait = (ms) => new Promise((r) => setTimeout(r, reduce ? 0 : ms));
  const out = (o) => {
    if (o.file) return `<div class="bub out pop"><div class="filebub"><i><svg><use href="#doc"/></svg></i><div><b>${o.file}</b><small>${o.size}</small></div></div><span class="time">10:09 ✓✓</span></div>`;
    if (o.voice) return `<div class="bub out pop"><div class="vn"><i class="play"></i><span class="wave">${WAVE}</span><small>${o.voice}</small></div><span class="time">10:09 ✓✓</span></div>`;
    if (o.link) return `<div class="bub out pop"><span class="link">${o.link}</span><span class="time">10:09 ✓✓</span></div>`;
    return `<div class="bub out pop"><span class="fwd">${km() ? "បញ្ជូនបន្តពី" : "Forwarded from"} ${o.fwd}</span>${t(o.text)}<span class="time">10:09 ✓✓</span></div>`;
  };
  const reply = (lines) => `
    <div class="grp">
      <div class="dots" aria-hidden="true"><i></i><i></i><i></i></div>
      <div class="bub in pop">${lines.map((l) => `<p>${l}</p>`).join("")}
        <div class="quote"><span>ℹ️ ${km() ? "ព័ត៌មានលម្អិត" : "Details"}</span><svg><use href="#down"/></svg></div>
        <span class="time">10:09</span>
      </div>
      <div class="kbs pop">
        <div class="kb">🚩 ${km() ? "រាយការណ៍ថាជាការបោកប្រាស់" : "Report as a scam"}</div>
        <div class="kb2"><span>👍 ${km() ? "ត្រូវ" : "Right"}</span><span>👎 ${km() ? "ខុស" : "Wrong"}</span></div>
      </div>
    </div>`;
  const DUR = 8200;
  const play = async (i) => {
    const me = ++run;
    current = i;
    picks.querySelectorAll(".pick").forEach((b) => b.setAttribute("aria-pressed", Number(b.dataset.i) === i));
    if (matchMedia("(max-width: 720px)").matches) {
      const chip = picks.children[i];
      if (chip) picks.scrollTo({ left: chip.offsetLeft - parseFloat(getComputedStyle(picks).paddingLeft), behavior: reduce ? "auto" : "smooth" });
    }
    picks.style.setProperty("--dur", DUR + "ms");
    const d = DEMO[i];
    leaders.classList.remove("on");
    thread.classList.add("fade");
    await wait(250); if (me !== run) return;
    thread.innerHTML = `<div class="day">${km() ? "ថ្ងៃនេះ" : "Today"}</div>` + out(d.out) + reply(t(d.reply));
    thread.classList.remove("fade");
    status.textContent = "bot"; status.classList.remove("typing");
    const [o, bubIn, kb] = thread.querySelectorAll(".pop");
    await wait(150); if (me !== run) return;
    o.classList.add("on");
    await wait(450); if (me !== run) return;
    status.textContent = km() ? "កំពុងវាយ…" : "typing…"; status.classList.add("typing"); thread.classList.add("typing");
    await wait(900); if (me !== run) return;
    status.textContent = "bot"; status.classList.remove("typing"); thread.classList.remove("typing");
    bubIn.classList.add("on");
    await wait(300); if (me !== run) return;
    kb.classList.add("on");
    await wait(450); if (me !== run) return;
    layoutNotes();
    notes.classList.add("on"); leaders.classList.add("on");
  };
  picks.addEventListener("animationend", () => autoplay && play((current + 1) % DEMO.length));
  picks.addEventListener("click", (e) => {
    const b = e.target.closest(".pick");
    if (!b) return;
    autoplay = false;
    picks.classList.remove("auto");
    play(Number(b.dataset.i));
  });
  let started = false;
  new IntersectionObserver(([e]) => {
    if (e.isIntersecting && !started) { started = true; play(0); }
    picks.querySelectorAll(".bar").forEach((b) => (b.style.animationPlayState = e.isIntersecting ? "running" : "paused"));
  }, { threshold: 0.3 }).observe($("demo"));

  // ---------- FAQ ----------

  $("faq-list").addEventListener("click", (e) => {
    const b = e.target.closest("button");
    if (!b) return;
    const qa = b.parentElement;
    const open = !qa.hasAttribute("data-open");
    qa.toggleAttribute("data-open", open);
    b.setAttribute("aria-expanded", open);
  });

  // ---------- Floating nav: shown between the hero and the closing ----------

  const dock = $("dock");
  let pastHero = false, atEnd = false;
  const sync = () => dock.classList.toggle("show", pastHero && !atEnd);
  new IntersectionObserver(([e]) => { pastHero = !e.isIntersecting && e.boundingClientRect.top < 0; sync(); }).observe(document.querySelector(".hero-foot"));
  new IntersectionObserver(([e]) => { atEnd = e.isIntersecting; sync(); }, { threshold: 0.2 }).observe($("end"));
  const sections = ["replies", "checks", "privacy", "faq"].map($);
  const navSpy = new IntersectionObserver((entries) => {
    entries.forEach((e) => {
      if (e.isIntersecting) dock.querySelectorAll(".opt").forEach((a) => a.classList.toggle("here", a.getAttribute("href") === "#" + e.target.id));
    });
  }, { rootMargin: "-45% 0px -50% 0px" });
  sections.forEach((s) => navSpy.observe(s));

  // ---------- Theme ----------

  // Follows the device's light or dark setting, live, until the visitor picks one; the pick is remembered.
  const syncSegs = () => document.querySelectorAll(".seg").forEach((seg) => {
    const opts = [...seg.querySelectorAll("button, a")];
    seg.style.setProperty("--i", Math.max(0, opts.findIndex((b) => b.getAttribute("aria-pressed") === "true" || b.getAttribute("aria-current") === "page")));
  });
  const dark = matchMedia("(prefers-color-scheme: dark)");
  let themeChoice = "auto";
  try { themeChoice = localStorage.getItem("checksen-theme") || "auto"; } catch (e) {}
  const applyTheme = () => {
    body.dataset.theme = themeChoice === "auto" ? (dark.matches ? "night" : "paper") : themeChoice;
    document.querySelectorAll("[data-set-theme]").forEach((x) => x.setAttribute("aria-pressed", x.dataset.setTheme === themeChoice));
    syncSegs();
    requestAnimationFrame(() => { layoutNotes(); wire(); });
  };
  const chooseTheme = (choice) => {
    themeChoice = choice;
    try { choice === "auto" ? localStorage.removeItem("checksen-theme") : localStorage.setItem("checksen-theme", choice); } catch (e) {}
    applyTheme();
  };
  dark.addEventListener("change", applyTheme);
  document.addEventListener("click", (e) => {
    const pick = e.target.closest("[data-set-theme]");
    if (pick) chooseTheme(pick.dataset.setTheme);
    if (e.target.closest("#theme-btn")) chooseTheme(body.dataset.theme === "night" ? "paper" : "night");
  });
  applyTheme();

  addEventListener("resize", () => { fit(); layoutNotes(); wire(); });
  document.querySelectorAll(".tiles").forEach((row) => {
    const rail = document.createElement("div");
    rail.className = "rail";
    rail.innerHTML = "<i></i>";
    row.after(rail);
    const bar = rail.firstChild;
    const move = () => {
      const max = row.scrollWidth - row.clientWidth;
      bar.style.width = (row.clientWidth / row.scrollWidth) * 100 + "%";
      bar.style.transform = `translateX(${max > 0 ? (row.scrollLeft / max) * (row.scrollWidth / row.clientWidth - 1) * 100 : 0}%)`;
    };
    row.addEventListener("scroll", move, { passive: true });
    addEventListener("resize", move);
    requestAnimationFrame(move);
  });
  // The diagram slides in as it's revealed, so the lines are drawn again once it settles.
  $("flow").addEventListener("transitionend", (e) => e.target.id === "flow" && wire());
  watch(document);
  fit();
  wire();
  document.fonts.ready.then(() => {
    fit();
    wire();
    requestAnimationFrame(() => body.classList.add("ready"));
  });
})();
