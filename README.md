# amp-buzz

Turn the [Amp](https://ampcode.com) TUI into a **[buzz://](https://github.com/block/buzz) client**.

Every Amp thread becomes a private channel on your Buzz relay. Your prompts and Amp's replies are published there as signed Nostr events — so any Buzz client (Buzz Desktop, mobile, another agent) can follow the thread live, and remote collaborators can post messages that reach Amp as context on your next turn.

```
┌────────────────┐  prompts (your key)         ┌──────────────┐
│  Amp           │────────────────────────────▶│  Buzz relay  │
│  + this plugin │  replies (agent key)        │  channel     │
│                │────────────────────────────▶│  joah--…     │
│                │◀────────────────────────────│              │
└────────────────┘  remote messages → context  └──────┬───────┘
                                                      │
                                       ┌──────────────┴──────────────┐
                                       │ Buzz Desktop / mobile /     │
                                       │ other agents on the relay   │
                                       └─────────────────────────────┘
```

## How it maps to the Buzz protocol

- **One thread = one channel.** The first prompt of a thread creates a private channel named `<your-username>--<slug-of-first-prompt>` (the `parent--sub` convention, kind 9007), using your relay profile name. The channel is the durable record of the thread. [claude-code-buzz](https://github.com/joahg/claude-code-buzz) uses the same naming scheme.
- **Two identities.** Prompts are published under **your** Nostr key. Amp's replies are published under a dedicated **agent keypair** — never your key. The agent key carries a [NIP-OA](https://github.com/block/buzz/blob/main/docs/nips/NIP-OA.md) owner attestation minted with your key, so any client can verify you authorized it.
- **Explicit turns.** Remote messages never trigger Amp automatically. They appear live in the chat transcript as `<author>: …` messages and become context for your next prompt — but the plugin cancels their turns so they never dispatch inference.
- **Graceful degradation.** No relay configured → the plugin does nothing and Amp behaves exactly as before. The plugin also stays inert when the Amp process is itself a managed Buzz agent (`BUZZ_MANAGED_AGENT` or `BUZZ_AUTH_TAG` set) — those turns already live on the relay.
- **Client-only.** Works against a stock Buzz relay; no relay changes needed.

## Requirements

- [Amp](https://ampcode.com) with plugin support
- The [`buzz` CLI](https://github.com/block/buzz) on your `PATH` (handles all relay traffic and event signing)
- A Nostr identity that is a member of your Buzz relay

## Install

Copy [`buzz.ts`](./buzz.ts) into one of Amp's plugin directories:

```bash
# user-wide
curl -o ~/.config/amp/plugins/buzz.ts https://raw.githubusercontent.com/joahg/amp-buzz/main/buzz.ts

# or project-specific
cp buzz.ts /path/to/project/.amp/plugins/buzz.ts
```

Then restart Amp (or run `plugins: reload` from the command palette).

## Configure

Environment variables (or `~/.config/amp-buzz/config.json` with `relay_url` / `private_key`):

```bash
export BUZZ_RELAY_URL="wss://your-relay.example.com"
export BUZZ_PRIVATE_KEY="nsec1... or 64-char hex"   # your relay identity
```

On first use the plugin generates an agent keypair for this machine, mints its NIP-OA owner attestation with your key, and stores both in `~/.config/amp-buzz/agent.json` (mode 0600). To use an agent identity provisioned elsewhere (e.g. created in Buzz Desktop), place its `seckey`, `pubkey`, and `auth_tag` in that file — the plugin never overwrites a valid one.

## Use

Just talk to Amp. The first prompt creates the channel and mirrors from there on.

**Chat without prompting Amp.** Press `Tab` until the mode picker shows **buzz chat**, then type — your message posts to the thread's channel under your key and Amp never runs. In any mode, a prompt starting with `\` does the same (`\lunch?` posts "lunch?" to the channel — Amp's slash-command UI captures a leading `/`, so backslash is the escape).

**Live incoming messages.** New messages from collaborators appear directly in the Amp chat within seconds (10 s poll) as `<author>: …` messages. They never trigger Amp by themselves — the plugin cancels the turn before inference — but they become thread history, so Amp naturally sees them on your next prompt.

**Mention people.** Write `@name` in any mirrored prompt or chat message. Names resolve against channel members and relay profiles; a uniquely matching relay user is added to the channel and notified. Unresolvable `@text` is neutralized so sends never fail on incidental `@`s.

Command palette (`Buzz:` category):

| Command | What it does |
|---------|--------------|
| `Buzz: Status` | Show relay, identities, and this thread's channel |
| `Buzz: Invite` | Search relay users by name (or paste a pubkey/npub) and add them to the thread channel |
| `Buzz: Chat` | Post channel chat under your key — visible to collaborators, does **not** prompt Amp |
| `Buzz: Catch up` | Show new remote messages now (they still reach Amp on your next turn) |

## What is (and isn't) mirrored

Mirrored: your prompts, Amp's reply text per turn.
Not mirrored: tool calls, thinking, streaming chunks, file contents. The channel carries the conversation, not the firehose. Messages are truncated at 8 000 characters.

## State

| Path | Contents |
|------|----------|
| `~/.config/amp-buzz/agent.json` | Agent keypair + NIP-OA attestation |
| `~/.config/amp-buzz/sessions/<thread-id>.json` | Thread → channel mapping, poll cursor |
| `~/.config/amp-buzz/error.log` | Failures (the plugin never blocks your thread) |

## Development

```bash
node --test test/nostr.test.ts   # BIP-340 + NIP-OA test vectors (Node ≥ 22.6)
```

The plugin is a single dependency-free TypeScript file: the embedded secp256k1/Schnorr/bech32 code is used only for one-time agent identity setup; all relay traffic goes through the `buzz` CLI.

## License

Apache-2.0
