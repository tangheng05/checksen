// Replies are the bot's real output for these messages (rules only), generated from src/verdict.rs.
const ADVICE_KM = "⚠️ មុនបង់ប្រាក់ សូមពិនិត្យឈ្មោះអ្នកទទួល និងចំនួនទឹកប្រាក់ ក្នុងកម្មវិធីធនាគាររបស់អ្នកជានិច្ច។";
const ADVICE_EN = "⚠️ Before paying, always check the recipient's name and the amount in your bank app.";

const SAMPLES = {
  otp: {
    message: "សួស្តីបង ខ្ញុំមកពីធនាគារ ABA។ គណនីរបស់បងនឹងត្រូវបង្កកក្នុងរយៈពេល ២៤ម៉ោង។ សូមផ្ញើលេខកូដ OTP ដែលបងទើបទទួលបាន មកខ្ញុំភ្លាមៗ ដើម្បីដោះសោ។",
    messageEn: "Hi, I'm from ABA Bank. Your account will be frozen within 24 hours. Send me the OTP code you just received right away to unlock it.",
    level: "high",
    label: "🔴 ហានិភ័យខ្ពស់",
    labelEn: "🔴 High risk",
    reasons: [
      "សារនេះសុំលេខកូដ OTP ឬលេខសម្ងាត់។ ធនាគារ និងក្រុមហ៊ុនពិតៗ មិនដែលសុំលេខទាំងនេះទេ។ កុំប្រាប់នរណាម្នាក់ឡើយ។",
      "សារនេះប្រញាប់ឱ្យអ្នកធ្វើភ្លាមៗ។",
    ],
    reasonsEn: [
      "This message asks for an OTP code or password. Real banks and companies never ask for these. Don't tell anyone.",
      "This message pushes you to act right away.",
    ],
  },
  khqr: {
    photo: true,
    messageEn: "A photo of a KHQR code someone sent to pay into.",
    level: "high",
    label: "🔴 ហានិភ័យខ្ពស់",
    labelEn: "🔴 High risk",
    reasons: ["QR នេះអាចត្រូវគេកែ ឬខូច (លេខផ្ទៀងផ្ទាត់មិនត្រូវ)។ កុំបង់ប្រាក់តាម QR នេះ។"],
    reasonsEn: ["This QR may have been edited or damaged (its check digits don't match). Don't pay with this QR."],
  },
  loan: {
    message: "កម្ចីអនឡាញ អត់ទ្រព្យធានា អនុម័តភ្លាម! គ្រាន់តែផ្ញើអត្តសញ្ញាណប័ណ្ណ និងរូប selfie មក។",
    messageEn: "Online loan, no collateral, instant approval! Just send your ID card and a selfie.",
    level: "suspicious",
    label: "🟠 គួរឱ្យសង្ស័យ",
    labelEn: "🟠 Suspicious",
    reasons: ["សារនេះសន្យាឱ្យខ្ចីលុយងាយៗ មិនបាច់មានអ្នកធានា ឬទ្រព្យធានា។"],
    reasonsEn: ["This message promises an easy loan with no guarantor or collateral."],
  },
  job: {
    message: "ជ្រើសរើសបុគ្គលិកវាយអក្សរ និងឆាត ប្រាក់ខែ $1000 នៅប៉ោយប៉ែត។ មិនត្រូវការបទពិសោធន៍។",
    messageEn: "Hiring typing and chat staff, salary $1000, in Poipet. No experience needed.",
    level: "suspicious",
    label: "🟠 គួរឱ្យសង្ស័យ",
    labelEn: "🟠 Suspicious",
    reasons: [
      "សារនេះសន្យាការងារស្រួលៗ តែបានលុយច្រើនពេក ដូចជាចុចឡាយ ឬវាយអក្សរ។",
      "សារនេះផ្សាយការងារវាយអក្សរ ឆាត ឬ call center ប្រាក់ខែខ្ពស់ ដែលតែងជាការបោកទៅធ្វើការក្នុងទីតាំងបោកប្រាស់។ គេអាចដកលិខិតឆ្លងដែនរបស់អ្នក ហើយបង្ខំឱ្យធ្វើការ។",
    ],
    reasonsEn: [
      "This message promises easy work for too much money, like clicking likes or typing.",
      "This message advertises high-paid typing, chat or call-centre work, a common way of luring people into scam compounds. They may take your passport and force you to work.",
    ],
  },
  family: {
    message: "ម៉ាក់ផ្ញើលុយ $50 ទៅគណនីកូនហើយ ទិញសៀវភៅណា",
    messageEn: "Mum sent $50 to your account, go buy your books.",
    level: "none",
    label: "⚪ មិនទាន់ឃើញសញ្ញាបោកប្រាស់ទេ",
    labelEn: "⚪ No scam signs found yet",
    reasons: ["មិនឃើញពាក្យដែលអ្នកបោកប្រាស់តែងប្រើទេ តែសូមនៅតែប្រយ័ត្ន។"],
    reasonsEn: ["No words that scammers usually use, but stay careful."],
  },
};

const english = document.documentElement.lang === "en";
const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const thread = document.querySelector(".thread");
const buttons = document.querySelectorAll(".chips button");
let playing = 0;

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text) node.textContent = text;
  return node;
}

function gloss(text) {
  return english ? element("span", "gloss", text) : null;
}

function userBubble(sample) {
  if (sample.photo) {
    const bubble = element("div", "bubble user photo");
    const card = element("div", "khqr-card");
    card.setAttribute("role", "img");
    card.setAttribute("aria-label", english ? "Photo of a KHQR code" : "រូបថតកូដ KHQR");
    card.append(element("b", "", "KHQR"), element("i"));
    bubble.append(card);
    const note = gloss(sample.messageEn);
    if (note) bubble.append(note);
    return bubble;
  }
  const bubble = element("div", "bubble user", sample.message);
  bubble.lang = "km";
  const note = gloss(sample.messageEn);
  if (note) bubble.append(note);
  return bubble;
}

function botBubble(sample) {
  const bubble = element("div", "bubble bot");
  bubble.lang = "km";
  bubble.append(element("span", `level ${sample.level}`, sample.label));
  bubble.append(document.createTextNode([...sample.reasons, "", ADVICE_KM].join("\n")));
  const note = gloss([sample.labelEn, ...sample.reasonsEn, "", ADVICE_EN].join("\n"));
  if (note) {
    note.lang = "en";
    bubble.append(note);
  }
  return bubble;
}

function play(id) {
  const sample = SAMPLES[id];
  const run = ++playing;
  buttons.forEach((button) => button.setAttribute("aria-pressed", String(button.dataset.sample === id)));
  thread.replaceChildren(userBubble(sample));
  if (reducedMotion) {
    thread.append(botBubble(sample));
    return;
  }
  const typing = element("div", "typing");
  typing.setAttribute("aria-hidden", "true");
  typing.append(element("span"), element("span"), element("span"));
  thread.append(typing);
  setTimeout(() => {
    if (run !== playing) return;
    const reply = botBubble(sample);
    reply.classList.add("reveal");
    typing.replaceWith(reply);
  }, 700);
}

document.documentElement.classList.add("js");
buttons.forEach((button) => button.addEventListener("click", () => play(button.dataset.sample)));
