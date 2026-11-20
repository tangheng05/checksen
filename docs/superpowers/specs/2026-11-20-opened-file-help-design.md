# Help for people who already opened a bad file

**Why:** after a 🔴 file warning, people ask "I already opened it, what now?". The bot answers "I can only check messages…", which is useless when they need help most.

**Goals:** useful, simple steps; no extra taps or questions.

**Non-goals:** device buttons, AI-written answers, conversation memory.

**Constraints:** all text is fixed Khmer/English in `verdict.rs`; never say "safe".

## Approaches

- **Steps per file type, no questions (picked).** The bot already knows what the file is (or what's inside the archive), so it says which device is at risk and what to do there.
- Device buttons under the warning. One more tap and more clutter.
- AI-written answers. Could give wrong advice; breaks the "model never writes replies" rule.

## Design

1. **Red file reply.** The "🆘 Already opened it?" fold depends on the most dangerous kind found (the file itself, or inside a zip/RAR):
   - Windows program (exe, scripts, shortcuts): only a Windows computer is at risk; phone or Mac, just delete it; Windows steps (Wi-Fi off, delete, Windows Security full scan, change passwords from the phone, Telegram devices, bank).
   - Android app: only Android is at risk; iPhone or computer, just delete it; Android steps (internet off, uninstall in Settings → Apps, check Accessibility / Install unknown apps, passwords, bank).
   - Web page: typed a password or code into it? change it now, Telegram devices, bank.
   - Anything else: the current general steps.
2. **Typed follow-up.** A new intent `opened_file` (rules + model) for "I opened/installed/clicked/downloaded it". When nothing in the message is flagged, the bot answers with short steps for apk/Android, exe/Windows and iPhone, then passwords and Telegram devices.

Left to the builder: exact wording, regexes, how the inner kind is carried.

## Follow-ups (added the same day)

**Why:** after a result, "is it real?" or "I opened it" got answers that ignored it, so the bot felt dumb.

**Design:** each private-chat verdict leaves a short `Context` per person for 30 minutes, in memory only: a recap (level and 👉 action) and, for flagged files and links, the opened steps. It holds only the bot's own text, never the message. A typed, unforwarded message with no link in a private chat is answered from it before the cache:
- "I opened it" → the file's or link's steps (otherwise the device question, as before);
- a question about the result ("is it real?", "ពិតអត់?", "what should I do?") → the recap.
Anything else goes through the normal check.
