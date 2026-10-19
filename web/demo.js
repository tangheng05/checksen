// Replies are the bot's real output for these samples, generated from src/verdict.rs.
const KM = document.documentElement.lang === "km";

const ADVICE = KM
  ? "⚠️ មុនពេលបង់ប្រាក់៖ សូមពិនិត្យឈ្មោះអ្នកទទួល និងចំនួនទឹកប្រាក់នៅក្នុងកម្មវិធីធនាគាររបស់អ្នកឱ្យបានហ្មត់ចត់ជានិច្ច។"
  : "⚠️ Before paying, always check the recipient's name and the amount in your bank app.";
const CHECKING = KM ? "🔍 កំពុងពិនិត្យ…" : "🔍 Checking…";
const REPORT = KM ? "🚩 រាយការណ៍ថាជាការបោកប្រាស់" : "🚩 Report as a scam";
const STEPS = {
  download: KM ? "ទាញយកឯកសារ" : "Download the file",
  scan: KM ? "ស្កេនរកមេរោគ" : "Scan for viruses",
  qr: KM ? "រក QR ក្នុងរូប" : "Look for a QR code",
};
const OPENED_FILE = KM
  ? "🆘 បើអ្នកបានបើកវារួចហើយ៖\n1. ក្នុង Telegram ចូល Settings → Devices ហើយបិទឧបករណ៍ដែលអ្នកមិនស្គាល់។\n2. ប្តូរលេខសម្ងាត់ Two-Step Verification។\n3. ស្កេនកុំព្យូទ័រ ឬទូរស័ព្ទរកមេរោគ ហើយចាកចេញពីកម្មវិធីធនាគារ។\n4. បើគណនីរបស់អ្នកត្រូវគេយកទៅបោកអ្នកដទៃ សូមតេទៅប៉ូលិសជាតិ លេខ 117។"
  : "🆘 If you already opened it:\n1. In Telegram, go to Settings → Devices and end any session you don't recognise.\n2. Change your Two-Step Verification password.\n3. Scan your computer or phone for viruses, and log out of your bank app.\n4. If your account was used to scam others, call the National Police on 117.";
const DETAILS = KM ? "ℹ️ ព័ត៌មានលម្អិត" : "ℹ️ Details";

const SAMPLES = {
  otp: {
    forward: {
      text: "សួស្តីបង ខ្ញុំមកពីធនាគារ ABA។ គណនីរបស់បងនឹងត្រូវបង្កកក្នុងរយៈពេល ២៤ម៉ោង។ សូមផ្ញើលេខកូដ OTP ដែលបងទើបទទួលបាន មកខ្ញុំភ្លាមៗ ដើម្បីដោះសោ។",
      gloss: "Hi, I'm from ABA Bank. Your account will be frozen within 24 hours. Send me the OTP code you just received right away to unlock it.",
    },
    reply: KM
      ? {
          level: "high",
          label: "🔴 ហានិភ័យខ្ពស់",
          lines: [
            "សារនេះមានការទាមទារលេខកូដ OTP ឬលេខសម្ងាត់។ ធនាគារ និងក្រុមហ៊ុនផ្លូវការ ដាច់ខាតមិនដែលសុំលេខទាំងនេះឡើយ។ សូមកុំប្រាប់ព័ត៌មាននេះទៅនរណាម្នាក់ឱ្យសោះ!",
            "👉 កុំឆ្លើយតប កុំប្រាប់លេខកូដ ហើយកុំផ្ទេរលុយ។",
          ],
          advice: true,
          fold: ["សារនេះមានចេតនាបង្ខំឱ្យអ្នកប្រញាប់ធ្វើសកម្មភាពភ្លាមៗ។"],
        }
      : {
          level: "high",
          label: "🔴 High risk",
          lines: [
            "This message asks for an OTP code or password. Real banks and companies never ask for these. Don't tell anyone.",
            "👉 Don't reply, don't share any code, and don't send money.",
          ],
          advice: true,
          fold: ["This message pushes you to act right away."],
        },
  },
  apk: {
    forward: { file: "ABA Mobile.apk", size: "6.2 MB" },
    steps: ["download", "scan"],
    reply: KM
      ? {
          level: "high",
          label: "🔴 ហានិភ័យខ្ពស់",
          lines: [
            "កម្មវិធីនេះប្រើឈ្មោះ ABA។ ធនាគារមិនដែលផ្ញើកម្មវិធីតាម Telegram ទេ។ សូមដំឡើងតែពី Play Store ឬ App Store ប៉ុណ្ណោះ។",
            "👉 កុំបើក ឬដំឡើងឯកសារនេះ ហើយលុបវាចោល។",
          ],
          card: [
            "📎 ABA Mobile․apk · កម្មវិធីទូរស័ព្ទ Android (.apk)",
            "📦 com․aba․mobile․update",
            "🔓 អាច៖ អាន SMS · គ្រប់គ្រងអេក្រង់ · បង្ហាញពីលើកម្មវិធីផ្សេង",
            "🛡️ ClamAV: មិនរកឃើញមេរោគ",
            "🛡️ MalwareBazaar: មិនមានក្នុងបញ្ជីមេរោគ",
            "🛡️ VirusTotal: មិនទាន់មានអ្នកណាស្កេនឯកសារនេះទេ",
          ],
          fold: ["កម្មវិធីនេះអាចអានសារ SMS និងគ្រប់គ្រងអេក្រង់របស់អ្នក ដូចកម្មវិធីដែលលួចលុយពីគណនីធនាគារ។", "", OPENED_FILE],
        }
      : {
          level: "high",
          label: "🔴 High risk",
          lines: [
            "This app uses the name ABA. Banks never send apps over Telegram. Only install apps from the Play Store or App Store.",
            "👉 Don't open or install this file. Delete it.",
          ],
          card: [
            "📎 ABA Mobile․apk · an Android app (.apk)",
            "📦 com․aba․mobile․update",
            "🔓 Can: read SMS · control the screen · draw over apps",
            "🛡️ ClamAV: no virus found",
            "🛡️ MalwareBazaar: not on its malware list",
            "🛡️ VirusTotal: nobody has scanned this file yet",
          ],
          fold: ["This app can read your text messages and take over your screen, the way apps that steal from bank accounts work.", "", OPENED_FILE],
        },
  },
  link: {
    forward: { link: "https://aba-verify-login.top/account", site: "ABA Bank Login" },
    reply: KM
      ? {
          level: "high",
          label: "🔴 ហានិភ័យខ្ពស់",
          lines: ["ឈ្មោះគេហទំព័រនេះស្រដៀង ABA តែមិនមែនគេហទំព័រផ្លូវការទេ។", "👉 កុំបើកតំណនេះ ហើយកុំបញ្ចូលព័ត៌មានអ្វីទាំងអស់។"],
          advice: true,
          fold: [
            "គេហទំព័រនេះទើបបង្កើតថ្មី មិនទាន់បាន ៣០ ថ្ងៃផង។\n• គេហទំព័រ៖ aba-verify-login[.]top\n• ចំណងជើងទំព័រ៖ ABA Bank Login\n• ម្ចាស់គេហទំព័រ៖ មិនមែនជាគេហទំព័រល្បី ដែល CheckSen ស្គាល់ទេ\n• អាយុគេហទំព័រ៖ ៣ថ្ងៃ",
            "",
            "មិនត្រូវបញ្ចូលលេខសម្ងាត់ ឬលេខកូដ OTP តាមតំណភ្ជាប់ (Link) ណាមួយឡើយ។ បើចង់ពិនិត្យមើលគណនី សូមបើកចូលកម្មវិធីធនាគាររបស់អ្នកដោយផ្ទាល់។",
          ],
          report: true,
        }
      : {
          level: "high",
          label: "🔴 High risk",
          lines: ["This site's name looks like ABA, but it isn't the official site.", "👉 Don't open this link or enter anything on it."],
          advice: true,
          fold: [
            "This site was created less than 30 days ago.\n• Site: aba-verify-login[.]top\n• Page title: ABA Bank Login\n• Owner: not a well-known site that CheckSen knows\n• Site age: 3 days",
            "",
            "Never enter a password or OTP code through a link. To check your account, open your bank app yourself.",
          ],
          report: true,
        },
  },
  khqr: {
    forward: { photo: { name: "SOK DARA", amount: "50,000", currency: "KHR" } },
    gloss: "A photo of a KHQR code someone sent you to pay into.",
    steps: ["qr"],
    reply: KM
      ? {
          level: "high",
          label: "🔴 ហានិភ័យខ្ពស់",
          lines: ["QR នេះអាចត្រូវគេកែ ឬខូច (លេខផ្ទៀងផ្ទាត់មិនត្រូវ)។ កុំបង់ប្រាក់តាម QR នេះ។"],
          advice: true,
        }
      : {
          level: "high",
          label: "🔴 High risk",
          lines: ["This QR may have been edited or damaged (its check digits don't match). Don't pay with this QR."],
          advice: true,
        },
  },
  job: {
    forward: {
      text: "ជ្រើសរើសបុគ្គលិកវាយអក្សរ និងឆាត ប្រាក់ខែ $1000 នៅប៉ោយប៉ែត។ មិនត្រូវការបទពិសោធន៍។ ទាក់ទង 097 555 1234",
      gloss: "Hiring typing and chat staff, salary $1000, in Poipet. No experience needed. Call 097 555 1234",
    },
    reply: KM
      ? {
          level: "suspicious",
          label: "🟠 គួរឱ្យសង្ស័យ",
          lines: ["សារនេះសន្យាការងារស្រួលៗ តែបានលុយច្រើនពេក ដូចជាចុចឡាយ ឬវាយអក្សរ។", "👉 សូមផ្ទៀងផ្ទាត់តាមលេខ ឬកម្មវិធីផ្លូវការសិន មុនពេលធ្វើតាមសារនេះ។"],
          advice: true,
          fold: ["សារនេះផ្សាយការងារវាយអក្សរ ឆាត ឬ call center ប្រាក់ខែខ្ពស់ ដែលតែងជាការបោកទៅធ្វើការក្នុងទីតាំងបោកប្រាស់។ គេអាចដកលិខិតឆ្លងដែនរបស់អ្នក ហើយបង្ខំឱ្យធ្វើការ។"],
          report: true,
        }
      : {
          level: "suspicious",
          label: "🟠 Suspicious",
          lines: ["This message promises easy work for too much money, like clicking likes or typing.", "👉 Check through an official number or app before you do what it asks."],
          advice: true,
          fold: ["This message advertises high-paid typing, chat or call-centre work, a common way of luring people into scam compounds. They may take your passport and force you to work."],
          report: true,
        },
  },
  mum: {
    forward: {
      text: "ម៉ាក់ផ្ញើលុយ $50 ទៅគណនីកូនហើយ ទិញសៀវភៅណា",
      gloss: "Mum sent $50 to your account, go buy your books.",
    },
    reply: KM
      ? { level: "none", label: "⚪ មិនទាន់រកឃើញសញ្ញាបោកប្រាស់ទេ", lines: ["មិនឃើញពាក្យដែលអ្នកបោកប្រាស់តែងប្រើទេ តែសូមនៅតែប្រយ័ត្ន។"], advice: true }
      : { level: "none", label: "⚪ No scam signs found yet", lines: ["No words that scammers usually use, but stay careful."], advice: true },
  },
};

const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const thread = document.querySelector(".thread");
const buttons = document.querySelectorAll(".tray button");
let playing = 0;

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function withGloss(bubble, text) {
  if (!KM && text) bubble.append(element("span", "gloss", text));
  return bubble;
}

function attachment(className, icon, title, meta) {
  const bubble = element("div", `bubble user ${className}`);
  const thumb = element("span", `thumb ${className}`, icon);
  thumb.setAttribute("aria-hidden", "true");
  const label = element("span");
  label.append(element("b", "", title), element("small", "", meta));
  bubble.append(thumb, label);
  return bubble;
}

function khqrCard({ name, amount, currency }) {
  const card = element("div", "khqr-card");
  card.setAttribute("role", "img");
  card.setAttribute("aria-label", KM ? `រូបថតកូដ KHQR៖ ${name} ${amount} ${currency}` : `Photo of a KHQR code: ${name}, ${amount} ${currency}`);
  const head = element("div", "khqr-head");
  head.append(element("b", "", "KHQR"));
  const body = element("div", "khqr-body");
  const total = element("span", "khqr-amount", amount);
  total.append(element("small", "", currency));
  body.append(element("span", "khqr-name", name), total);
  const code = element("div", "khqr-code");
  const qr = element("img");
  qr.src = "/assets/khqr-demo.svg";
  qr.alt = "";
  code.append(qr, element("span", "khqr-mark", "៛"));
  card.append(head, body, element("hr"), code);
  return card;
}

function forwarded(sample) {
  const { forward } = sample;
  if (forward.file) return attachment("file", "APK", forward.file, forward.size);
  if (forward.link) return attachment("link", "🔗", forward.link, forward.site);
  if (forward.photo) {
    const bubble = element("div", "bubble user photo");
    bubble.append(khqrCard(forward.photo));
    return withGloss(bubble, sample.gloss);
  }
  const bubble = element("div", "bubble user", forward.text);
  bubble.lang = "km";
  return withGloss(bubble, forward.gloss);
}

function reply({ level, label, lines, card, advice, fold }) {
  const bubble = element("div", "bubble bot");
  bubble.append(element("b", `level ${level}`, label));
  bubble.append(document.createTextNode(lines.join("\n")));
  for (const block of [card && card.join("\n"), advice && ADVICE]) {
    if (!block) continue;
    bubble.append(element("span", "gap"), document.createTextNode(block));
  }
  if (fold) {
    const details = element("details", "fold");
    details.append(element("summary", "", DETAILS), element("p", "", fold.join("\n")));
    bubble.append(details);
  }
  return bubble;
}

function checking(done, current) {
  const lines = [...done.map((step) => `✅ ${STEPS[step]}`), `⏳ ${STEPS[current]}…`];
  const bubble = element("div", "bubble bot checking");
  bubble.append(element("b", "", CHECKING), document.createTextNode(lines.join("\n")));
  return bubble;
}

function finish(sample, run) {
  if (run !== playing) return;
  const parts = [reply(sample.reply)];
  if (sample.reply.report) {
    const row = element("div", "bot-buttons");
    row.append(element("span", "", REPORT));
    parts.push(row);
  }
  if (!reducedMotion) parts.forEach((part) => part.classList.add("arrive"));
  thread.querySelector(".checking, .typing")?.remove();
  thread.append(...parts);
}

function play(id) {
  const sample = SAMPLES[id];
  const run = ++playing;
  buttons.forEach((button) => button.setAttribute("aria-pressed", String(button.dataset.sample === id)));
  const message = forwarded(sample);
  thread.replaceChildren(message);
  if (reducedMotion) {
    finish(sample, run);
    return;
  }
  message.classList.add("arrive");
  const steps = sample.steps || [];
  if (!steps.length) {
    const typing = element("div", "typing");
    typing.setAttribute("aria-hidden", "true");
    typing.append(element("span"), element("span"), element("span"));
    setTimeout(() => run === playing && thread.append(typing), 250);
    setTimeout(() => finish(sample, run), 1000);
    return;
  }
  // Like the bot, one status message ticks off each step and then becomes the reply.
  steps.forEach((step, index) => {
    setTimeout(() => {
      if (run !== playing) return;
      const status = checking(steps.slice(0, index), step);
      const previous = thread.querySelector(".checking");
      if (previous) previous.replaceWith(status);
      else thread.append(status);
    }, 300 + index * 650);
  });
  setTimeout(() => finish(sample, run), 300 + steps.length * 650 + 300);
}

document.documentElement.classList.remove("no-js");
buttons.forEach((button) => button.addEventListener("click", () => play(button.dataset.sample)));
