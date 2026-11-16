# Receiptd Launch Checklist

All content below is ready to copy-paste. You post — no credentials or tokens needed from me.

---

## Launch Checklist

- [ ] **Merge all branches** (done — see git log)
- [ ] **GitHub description + topics set** (done — `.github/GITHUB_SETUP_DONE`)
- [ ] **Demo GIF in README** (`static/tamper-demo.gif` — embedded at line ~53 of README.md)
- [ ] **Post to Show HN** — Tuesday or Wednesday, 9am US Eastern
- [ ] **Post Twitter/X thread** — same day as Show HN, within the hour
- [ ] **Post Reddit r/LocalLLaMA** — same day
- [ ] **Post Reddit r/MachineLearning** — same day (can use the same post)
- [ ] **Post Dev.to article** — write from `docs/social-media/devto-outline.md`
- [ ] **Monitor and reply** — respond to every comment for the opening 24 hours

---

## Show HN Post

**Where:** https://news.ycombinator.com/submit  
**Best time:** Tuesday or Wednesday, 9am US Eastern  
**Title:** (must start with "Show HN:")

```
Show HN: Receiptd — fail-closed gate for hooked AI agent tool calls, with a hash-chained audit log
```

**Text body:**

```
I was worried my local AI agent would go rogue. So I built Receiptd—a fail-closed gate for hooked AI agent tool calls, with a hash-chained audit log:

1. Tamper-evident audit log — each logged row is hashed into a chain. If someone (including the agent) tries to cover its tracks, the hash chain catches it. Unlike append-only logs, an altered record fails the hash-chain check.

2. Tamper test — replace the audit.db file and run verify-chain.py. It detects the swap. Works in CI.

3. Pre-execution gate — hooked tool calls are checked before they run. Exit 2 blocks. A tool that is not hooked is not checked.

It's open source, runs locally, and includes an iPhone PWA for emergency control from anywhere.

The threat model is honest about what it does not catch (root-level host compromise, a hook that never starts, prompt injection on the model itself). For the hooked calls it does see, you get a signed receipt and a hash chain you can check offline.

Looking for feedback on the threat model, and I'm curious if people would find per-skill access rules or an external witness for the chain tip useful.

Looking for feedback on the threat model, and I'm curious if people would find RBAC per skill or distributed Merkle-tree anchoring useful.

Demo: 45-second asciinema showing governance check → tamper simulation → detection (static/tamper-demo.gif in the repo).
```

**URL to submit:** `https://github.com/NickAltstein/receiptd`

**HN tips:**
- Reply to every comment in the opening 24 hours — HN ranks by engagement velocity
- If asked "why not use X": answer is X doesn't have tamper detection / X does not run locally / X requires trust in the provider
- If crypto confusion appears: "No tokens, no DAO, no blockchain — just agentic AI security tooling"

Full draft: [`docs/social-media/show-hn-post.md`](docs/social-media/show-hn-post.md)

---

## Twitter / X Thread

Post as a thread. Replace `[GIF_LINK]` with the direct URL to `static/tamper-demo.gif` on GitHub.

**Tweet 1 — Hook**
```
Giving an AI agent access to your files, APIs, and shell is terrifying.

Hallucinations become destructive actions. A prompt injection can exfiltrate your secrets.

So I built Receiptd: a hash-chained audit log and a fail-closed gate for hooked AI agent tool calls.

Open source. No tokens. A hash chain you can check. 🧵
```

**Tweet 2 — Demo**
```
Here's what it looks like when Receiptd catches a tamper attempt:

[GIF_LINK]

Every row in the audit DB stores SHA-256(prev_hash || payload). Mutate one byte anywhere — even after bypassing database triggers — and the hash-chain check fails.

Run ./tests/tamper-test.sh
```

**Tweet 3 — The 5-Gate Governance Check**
```
Receiptd runs a 5-gate governance check against your agent:

1. Is the agent process running and responding?
2. Is the audit chain intact? (no tampered rows)
3. Are all skills git-versioned with committed changes?
4. Has the model drifted from its signed behavioral baseline?
5. Is the health endpoint reporting clean?

Pure deterministic logic. No AI guessing about AI.

./governance-check.sh → "AGENT GOVERNANCE INTACT"
```

**Tweet 4 — The Hard Problem**
```
The weakest link: what if an attacker replaces the entire audit.db?

verify-chain.py would accept the replacement chain.

So Receiptd posts the chain tip hash to Telegram hourly. Full DB replacement produces a new tip that doesn't match published history.

A replaced database then disagrees with the published tip.
```

**Tweet 5 — CTA**
```
Receiptd is open source, MIT licensed, runs on Docker.

If you run a local AI agent (Hermes, anything OpenAI-compatible), Receiptd wraps hooked tool calls without replacing the agent.

GitHub: https://github.com/NickAltstein/receiptd

Looking for feedback on the threat model — especially attack vectors I missed.

What would you want in a kill switch for your agent?
```

Full draft: [`docs/social-media/twitter-thread.md`](docs/social-media/twitter-thread.md)

---

## Reddit Posts

Use the same post for both **r/LocalLLaMA** and **r/MachineLearning** (post a few hours apart).

**Title:**
```
I was worried my local AI agent would go rogue, so I built a hash-chained audit log with a kill switch. Open source—looking for feedback on the threat model.
```

**Body:**
```
I've been running a local AI agent (Hermes from Nous Research) to handle real tasks: competitor monitoring, daily briefings, code governance checks. It has shell access, web access, file access.

That scared me. An agent that can do things can also do the wrong things.

So I built Receiptd — a fail-closed gate for hooked tool calls that can sit in front of a Hermes-compatible agent without modifying the agent itself.

**What it does:**

- **Hash-chained SQLite audit log**: each logged row is SHA-256 chained (SHA-256(prev_hash || payload)). Mutate any row — even after bypassing database triggers — and verify-chain.py catches it. CI-tested on every push.
- **5-gate deterministic governance check**: process liveness, audit chain integrity, skill version pinning, behavioral drift against a signed baseline, health endpoint.
- **Kill switches**: agent-stop.sh (graceful) and agent-lockdown.sh (network isolation). Both writes are themselves audit-logged.
- **Drift detection**: 5 benchmark questions, bigram cosine similarity, threshold 0.85. Catches model swaps and config changes that shift behavior.
- **iPhone PWA**: full-screen Open WebUI from Safari home screen.

**The honest threat model** (from THREAT_MODEL.md):

- ✅ Catches: row mutation, deletion, mid-chain insertion, mutation after trigger bypass
- ❌ Does NOT catch: attacker replacing the entire DB, log omission (agent action never logged), root-level host compromise, prompt injection on the agent itself

The DB replacement attack is the one I'm most worried about. The roadmap item is posting the chain tip hash to Telegram hourly — so a full replacement produces a tip that doesn't match published history.

**GitHub**: https://github.com/NickAltstein/receiptd

**Not crypto**: I'm aware there's a "Hermes" crypto project. This is completely unrelated — no tokens, no DAO, no blockchain. Just agentic AI security tooling.

---

What I'm genuinely looking for:

1. Attack vectors I haven't thought of in the threat model
2. Opinions on the drift detection approach (bigram cosine vs. embedding similarity)
3. Anyone who's tried to check what an agent did, instead of asking the model to report on itself

Happy to discuss the architecture in comments.
```

Full draft: [`docs/social-media/reddit-post.md`](docs/social-media/reddit-post.md)

---

## Dev.to Article

**Where:** https://dev.to/new  
**Title:** `Why I added a kill-switch and hash-chained audit logs to my AI agent (and why you should too)`  
**Tags:** `ai`, `security`, `autonomousagents`, `opensource`

Write from the outline in [`docs/social-media/devto-outline.md`](docs/social-media/devto-outline.md).

Key assets to embed:
- `static/tamper-demo.gif` — the tamper-test demo (already in repo)
- Output of `./governance-check.sh` — paste as a code block
- Link to `THREAT_MODEL.md`

Cross-post canonical URL from your GitHub Pages or personal blog if you have one.

---

## Posting Order

1. **Tuesday or Wednesday, 9am Eastern** — Submit the Show HN post before the other posts
2. **Within 1 hour of Show HN** — Post Twitter thread (link to GitHub, not HN post)
3. **Same day, afternoon** — Post r/LocalLLaMA
4. **Same day, evening** — Post r/MachineLearning
5. **Day 2** — Publish Dev.to article, share link on Twitter

Monitor HN comments and reply within minutes when possible — early engagement drives ranking.
