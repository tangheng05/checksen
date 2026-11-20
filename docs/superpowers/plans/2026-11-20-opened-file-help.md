# Opened-file help Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Tell people who already opened a bad file exactly what to do, for the device it can actually harm.

**Architecture:** `FileInfo` gains the dangerous kinds found inside an archive; `verdict` picks the "🆘 If you already opened it:" text from the file's kind. A new `Intent::OpenedFile` gives a fixed answer to "I opened it" messages.

**Tech Stack:** Rust, regex, teloxide.

**Spec:** `docs/superpowers/specs/2026-11-20-opened-file-help-design.md`

## Global Constraints

- All text is a fixed Khmer/English pair in `verdict.rs`; no reply says "safe" or សុវត្ថិភាព.
- Every variant keeps the heading "🆘 If you already opened it:" / "🆘 បើអ្នកបានបើកវារួចហើយ៖".
- Bump `RULES_VERSION`; run the eval.

## Review Focus

- An archive holding both an .exe and an .apk gets the general steps, not one device's.
- A RAR with a `.pdf` and a `.lnk` gets the Windows steps.
- "I opened it" inside a forwarded scam that the rules flag still gets the verdict, not the fixed answer.
- The model saying `other_question` must not override a rules `opened_file`.
- `.sh`, `.py`, `.docm` (FileKind::Script) and `.dmg` get the general steps.

---

### Task 1: Device-specific steps in file replies

**Files:** Modify `src/analyzers/file.rs`, `src/verdict.rs`

**Interfaces:**
- Produces: `FileInfo::inside: Vec<FileKind>`, the distinct dangerous kinds (not `WebPage`) of an archive's entries.

- [ ] Test in `verdict.rs`: `opened_steps_fit_the_device`: `.exe` → fold contains "only harm a Windows computer"; RAR with `a.pdf.lnk` → same; `.apk` → "only harm an Android phone"; `.html` → "typed"; RAR with `.exe` + `.apk` and `x.sh` → general steps (`OPENED_FILE`).
- [ ] Add `inside` to `FileInfo`, filled in `inspect` from archive entries.
- [ ] `fn opened_steps(info: &FileInfo) -> Text` in `verdict.rs`: kinds = `[real]` when real is dangerous, else `inside`; all `WindowsProgram | Shortcut` → `OPENED_WINDOWS`; all `AndroidApp` → `OPENED_ANDROID`; `WebPage` → `OPENED_PAGE`; else `OPENED_FILE`.
- [ ] `cargo test`, commit.

### Task 2: "I opened it" intent

**Files:** Modify `src/analyzers/intent.rs`, `src/analyzers/llm/mod.rs`, `src/verdict.rs`

- [ ] Tests in `intent.rs`: "ខ្ញុំបានបើកវាហើយ", "ខ្ញុំទាញយក ហើយចុចបើកវាហើយ ធ្វើម៉េច", "I already opened the file, what should I do?", "i clicked it and installed the app" → `OpenedFile`; "Click to open the file" → not. `decide(Some(OpenedFile), Some(OtherQuestion), ..)` → `OpenedFile`.
- [ ] `Intent::OpenedFile` (`opened_file`) after `AlreadyScammed` in `detect`; either side wins in `decide` after `AlreadyScammed`; model prompt line; `answer` → `OPENED_ANSWER`.
- [ ] Bump `RULES_VERSION`, `cargo fmt --check`, clippy, `cargo test`, `cargo run --bin eval`, commit.

### Task 3: Follow-ups with context

**Files:** `src/verdict.rs` (`Context`, `context(checks, kind)`), `src/analyzers/intent.rs` (`FollowUp`, `follow_up(text)`), `src/guard.rs` (`remember`, `context`, 30 min TTL), `src/bot.rs` (`Reply::context`, answer in `respond` before the cache).

- [ ] Tests: `follow_up` finds Opened / AboutIt and ignores "តើថ្ងៃនេះភ្លៀងទេ?"; `context` for a RAR with an .exe has a 🔴 recap and Windows steps, and a ⚪ file has no opened steps; the guard keeps a context per sender.
- [ ] fmt, clippy, tests, eval, commit.
