import assert from 'node:assert'
import { test } from 'node:test'
import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'

// STATE_DIR is resolved at module load, so point it at a temp dir before
// importing buzz.ts (this file must not import it statically).
const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'amp-buzz-test-'))
process.env.AMP_BUZZ_STATE_DIR = stateDir

const {
	bindSessionToChannel,
	createSessionChannel,
	custodianIdentity,
	deriveCustodianKeypair,
	generateKeypair,
	isEmptyThread,
	joinChannelAsAgent,
	leaveChannel,
	loadSession,
	verifyOwnerAttestation,
} = await import('../buzz.ts')

const logFile = path.join(stateDir, 'cli.log')
const ownerFlag = path.join(stateDir, 'owner.flag')
const handoffFlag = path.join(stateDir, 'handoff.flag')
const addFailFlag = path.join(stateDir, 'add-fail.flag')
const membersHideFlag = path.join(stateDir, 'members-hide.flag')
const msgsFailFlag = path.join(stateDir, 'msgs-fail.flag')
const membersFile = path.join(stateDir, 'members.list')
process.env.AMP_BUZZ_TEST_LOG = logFile
process.env.AMP_BUZZ_TEST_OWNER_FLAG = ownerFlag
process.env.AMP_BUZZ_TEST_HANDOFF_FLAG = handoffFlag
process.env.AMP_BUZZ_TEST_ADD_FAIL_FLAG = addFailFlag
process.env.AMP_BUZZ_TEST_MEMBERS_HIDE_FLAG = membersHideFlag
process.env.AMP_BUZZ_TEST_MSGS_FAIL_FLAG = msgsFailFlag
process.env.AMP_BUZZ_TEST_MEMBERS_FILE = membersFile

// Stub buzz CLI:
// - refuses `channels leave` while the owner flag is set and no ownership
//   handoff (add-member) has happened yet — like the relay's "cannot remove
//   the last owner" rule;
// - `channels add-member` fails while the add-fail flag is set, otherwise
//   records the pubkey so `channels members` reflects it;
// - `channels create` returns a channel id.
const stubBin = path.join(stateDir, 'buzz-stub.sh')
fs.writeFileSync(
	stubBin,
	`#!/bin/sh
echo "$@" >> "$AMP_BUZZ_TEST_LOG"
case "$1 $2" in
  "channels leave")
    if [ -f "$AMP_BUZZ_TEST_OWNER_FLAG" ] && [ ! -f "$AMP_BUZZ_TEST_HANDOFF_FLAG" ]; then
      echo "error: cannot remove the last owner — transfer ownership first" >&2
      exit 1
    fi
    echo '{"ok":true}'
    ;;
  "channels add-member")
    if [ -f "$AMP_BUZZ_TEST_ADD_FAIL_FLAG" ]; then
      echo "error: forbidden" >&2
      exit 1
    fi
    touch "$AMP_BUZZ_TEST_HANDOFF_FLAG"
    pk=""
    prev=""
    for a in "$@"; do
      if [ "$prev" = "--pubkey" ]; then pk="$a"; fi
      prev="$a"
    done
    if [ -n "$pk" ]; then echo "$pk" >> "$AMP_BUZZ_TEST_MEMBERS_FILE"; fi
    echo '{"ok":true}'
    ;;
  "messages get")
    if [ -f "$AMP_BUZZ_TEST_MSGS_FAIL_FLAG" ]; then
      echo "error: relay unavailable" >&2
      exit 1
    fi
    echo '[]'
    ;;
  "channels members")
    if [ -f "$AMP_BUZZ_TEST_MEMBERS_HIDE_FLAG" ]; then
      echo '[]'
    elif [ -f "$AMP_BUZZ_TEST_MEMBERS_FILE" ]; then
      printf '['
      first=1
      while IFS= read -r line; do
        [ "$first" = 1 ] || printf ','
        printf '{"pubkey":"%s"}' "$line"
        first=0
      done < "$AMP_BUZZ_TEST_MEMBERS_FILE"
      printf ']\\n'
    else
      echo '[]'
    fi
    ;;
  "channels create")
    echo '{"channel_id":"chan-created-1"}'
    ;;
  *) echo '{}' ;;
esac
`,
	{ mode: 0o755 },
)

const owner = generateKeypair()
const config = {
	relayUrl: 'wss://example.invalid',
	userSeckey: owner.seckey,
	userPubkey: owner.pubkey,
	buzzBin: stubBin,
	channelPrefix: 'amp',
	triggerPubkeys: [],
}

function readLog(): string[] {
	try {
		return fs.readFileSync(logFile, 'utf8').trim().split('\n').filter(Boolean)
	} catch {
		return []
	}
}

function resetCliState(): void {
	for (const f of [logFile, ownerFlag, handoffFlag, addFailFlag, membersHideFlag, msgsFailFlag, membersFile])
		fs.rmSync(f, { force: true })
}

async function testAgent(name: string) {
	const { mintOwnerAttestation } = await import('../buzz.ts')
	const kp = generateKeypair()
	return {
		seckey: kp.seckey,
		pubkey: kp.pubkey,
		authTag: mintOwnerAttestation(owner.seckey, kp.pubkey, ''),
		name,
	}
}

test('custodianIdentity mints once and persists across calls', () => {
	resetCliState()
	const a = custodianIdentity(config)
	const b = custodianIdentity(config)
	assert.strictEqual(a.pubkey, b.pubkey)
	assert.strictEqual(a.seckey, b.seckey)
	assert.notStrictEqual(a.pubkey, owner.pubkey)
	assert.ok(verifyOwnerAttestation(a.authTag, a.pubkey))
	assert.strictEqual(a.authTag[1], owner.pubkey)
	assert.ok(a.name.includes('custodian'))
	assert.ok(fs.existsSync(path.join(stateDir, 'custodian.json')))
	// only the first call touches the CLI (profile setup)
	const profileCalls = readLog().filter((l) => l.startsWith('users set-profile'))
	assert.strictEqual(profileCalls.length, 1)
})

test('custodianIdentity is re-derivable after state-directory loss', () => {
	resetCliState()
	const before = custodianIdentity(config)
	// A lost machine (e.g. a discarded Blox workstation) takes custodian.json
	// with it — the same owner key must still resolve the same custodian.
	fs.rmSync(path.join(stateDir, 'custodian.json'), { force: true })
	const after = custodianIdentity(config)
	assert.strictEqual(after.pubkey, before.pubkey)
	assert.strictEqual(after.seckey, before.seckey)
	const derived = deriveCustodianKeypair(config.userSeckey)
	assert.strictEqual(after.pubkey, derived.pubkey)
})

test('custodianIdentity never reuses a custodian cached by another account', () => {
	resetCliState()
	const mine = custodianIdentity(config)
	const other = generateKeypair()
	const otherConfig = { ...config, userSeckey: other.seckey, userPubkey: other.pubkey }
	// Switching Buzz accounts leaves the previous account's custodian.json
	// behind; it must never lend that account's authority to the new one.
	const theirs = custodianIdentity(otherConfig)
	assert.notStrictEqual(theirs.pubkey, mine.pubkey)
	assert.strictEqual(theirs.authTag[1], other.pubkey)
	const mineAgain = custodianIdentity(config)
	assert.strictEqual(mineAgain.pubkey, mine.pubkey)
	assert.strictEqual(mineAgain.authTag[1], owner.pubkey)
})

test('leaveChannel leaves directly when the agent is not the last owner', async () => {
	resetCliState()
	const { mintOwnerAttestation } = await import('../buzz.ts')
	const kp = generateKeypair()
	const agent = {
		seckey: kp.seckey,
		pubkey: kp.pubkey,
		authTag: mintOwnerAttestation(owner.seckey, kp.pubkey, ''),
		name: 'Amp (test-1)',
	}
	const res = leaveChannel(config, agent, 'chan-1')
	assert.deepStrictEqual(res, { left: true })
	const log = readLog()
	assert.strictEqual(log.filter((l) => l.startsWith('channels leave')).length, 1)
	assert.strictEqual(log.filter((l) => l.startsWith('channels add-member')).length, 0)
})

test('leaveChannel hands ownership to the custodian when the relay refuses', async () => {
	resetCliState()
	fs.writeFileSync(ownerFlag, '')
	const { mintOwnerAttestation } = await import('../buzz.ts')
	const kp = generateKeypair()
	const agent = {
		seckey: kp.seckey,
		pubkey: kp.pubkey,
		authTag: mintOwnerAttestation(owner.seckey, kp.pubkey, ''),
		name: 'Amp (test-2)',
	}
	const custodian = custodianIdentity(config)
	const res = leaveChannel(config, agent, 'chan-2')
	assert.deepStrictEqual(res, { left: true })
	const log = readLog()
	const handoff = log.find((l) => l.startsWith('channels add-member'))
	assert.ok(handoff, 'expected an ownership handoff add-member call')
	assert.ok(handoff.includes(custodian.pubkey))
	assert.ok(handoff.includes('--role owner'))
	assert.strictEqual(log.filter((l) => l.startsWith('channels leave')).length, 2)
})

test('createSessionChannel is custodian-owned with the session agent as bot', async () => {
	resetCliState()
	const agent = await testAgent('Amp (test-create)')
	const custodian = custodianIdentity(config)
	const channel = createSessionChannel(config, agent, 'T-create', 'hello world')
	assert.strictEqual(channel.id, 'chan-created-1')
	const log = readLog()
	const create = log.find((l) => l.startsWith('channels create'))
	assert.ok(create, 'expected a channels create call')
	const add = log.find((l) => l.startsWith('channels add-member'))
	assert.ok(add, 'expected the session agent added as a member')
	assert.ok(add.includes(agent.pubkey))
	assert.ok(add.includes('--role bot'))
	// The custodian (owner-by-creation) signs the bot add, not the user.
	const members = fs.readFileSync(membersFile, 'utf8').trim().split('\n')
	assert.deepStrictEqual(members, [agent.pubkey])
	assert.notStrictEqual(custodian.pubkey, agent.pubkey)
})

test('createSessionChannel fails when the session agent cannot be added', async () => {
	resetCliState()
	custodianIdentity(config)
	fs.writeFileSync(addFailFlag, '')
	const agent = await testAgent('Amp (test-create-fail)')
	assert.throws(
		() => createSessionChannel(config, agent, 'T-create-fail', 'hello'),
		/failed to add session agent/,
	)
})

test('joinChannelAsAgent verifies membership before reporting success', async () => {
	resetCliState()
	const agent = await testAgent('Amp (test-join)')
	const res = joinChannelAsAgent(config, 'chan-join-1', agent)
	assert.deepStrictEqual(res, { ok: true })
	const log = readLog()
	assert.ok(log.some((l) => l.startsWith('channels join')))
	assert.ok(
		log.some((l) => l.startsWith('channels add-member') && l.includes(agent.pubkey)),
		'expected the agent added as bot',
	)
	assert.ok(
		log.some((l) => l.startsWith('channels members')),
		'expected membership verified from the relay',
	)
})

test('joinChannelAsAgent compensates even when the add reports failure', async () => {
	resetCliState()
	fs.writeFileSync(addFailFlag, '')
	const agent = await testAgent('Amp (test-join-fail)')
	const res = joinChannelAsAgent(config, 'chan-join-2', agent)
	assert.strictEqual(res.ok, false)
	assert.ok(res.detail && /forbidden/.test(res.detail))
	// A "failed" add may still have committed on the relay (e.g. a timeout),
	// so the compensating leave of the destination runs unconditionally.
	const leaves = readLog().filter((l) => l.startsWith('channels leave'))
	assert.deepStrictEqual(leaves, ['channels leave --channel chan-join-2'])
})

test('joinChannelAsAgent trusts verified membership over a failed add report', async () => {
	resetCliState()
	const agent = await testAgent('Amp (test-join-ambiguous)')
	// The add command errors, but the relay actually committed it — the
	// membership check is the source of truth, so the join succeeds.
	fs.writeFileSync(addFailFlag, '')
	fs.appendFileSync(membersFile, agent.pubkey + '\n')
	const res = joinChannelAsAgent(config, 'chan-join-4', agent)
	assert.deepStrictEqual(res, { ok: true })
	assert.ok(!readLog().some((l) => l.startsWith('channels leave')))
})

test('joinChannelAsAgent undoes a join it cannot verify', async () => {
	resetCliState()
	fs.writeFileSync(membersHideFlag, '')
	const agent = await testAgent('Amp (test-join-unverified)')
	const res = joinChannelAsAgent(config, 'chan-join-3', agent)
	assert.strictEqual(res.ok, false)
	// add-member succeeded but membership couldn't be confirmed: the agent
	// must leave rather than remain as a dangling bot under a discarded key.
	const log = readLog()
	assert.ok(log.some((l) => l.startsWith('channels add-member')))
	assert.ok(
		log.some((l) => l.startsWith('channels leave') && l.includes('chan-join-3')),
		'expected a compensating leave',
	)
})

test('bindSessionToChannel saves the binding and reports history', async () => {
	resetCliState()
	const agent = await testAgent('Amp (test-bind)')
	const res = bindSessionToChannel(config, 'T-bind-ok', agent, {
		channel_id: 'chan-bind-1',
		name: 'bind-ok',
	})
	assert.ok(res, 'expected a committed binding')
	assert.strictEqual(res.state.channel_id, 'chan-bind-1')
	assert.deepStrictEqual(res.history, [])
	const saved = loadSession('T-bind-ok')
	assert.ok(saved && saved.channel_id === 'chan-bind-1')
	assert.strictEqual(saved.agent?.pubkey, agent.pubkey)
	// Committed: no compensating leave.
	assert.ok(!readLog().some((l) => l.startsWith('channels leave')))
})

test('bindSessionToChannel leaves the destination when history is unreadable', async () => {
	resetCliState()
	fs.writeFileSync(msgsFailFlag, '')
	const agent = await testAgent('Amp (test-bind-hist)')
	const res = bindSessionToChannel(config, 'T-bind-hist', agent, {
		channel_id: 'chan-bind-2',
		name: 'bind-hist',
	})
	assert.strictEqual(res, null)
	assert.strictEqual(loadSession('T-bind-hist'), null)
	assert.ok(
		readLog().some((l) => l === 'channels leave --channel chan-bind-2'),
		'expected a compensating leave of the destination',
	)
})

test('bindSessionToChannel leaves the destination when the state save fails', async () => {
	resetCliState()
	const agent = await testAgent('Amp (test-bind-save)')
	// Occupy the sessions directory path with a file so saveSession throws
	// after the destination membership was already established.
	const sessionsDir = path.join(stateDir, 'sessions')
	fs.rmSync(sessionsDir, { recursive: true, force: true })
	fs.writeFileSync(sessionsDir, '')
	try {
		assert.throws(() =>
			bindSessionToChannel(config, 'T-bind-save', agent, {
				channel_id: 'chan-bind-3',
				name: 'bind-save',
			}),
		)
	} finally {
		fs.rmSync(sessionsDir, { force: true })
	}
	assert.ok(
		readLog().some((l) => l === 'channels leave --channel chan-bind-3'),
		'expected a compensating leave of the destination',
	)
})

test('fetchChannelHistory distinguishes relay failure from empty history', async () => {
	resetCliState()
	const { fetchChannelHistory } = await import('../buzz.ts')
	const agent = await testAgent('Amp (test-history)')
	assert.deepStrictEqual(
		fetchChannelHistory(config, 'chan-hist-1', { seckey: agent.seckey, authTag: agent.authTag }),
		[],
	)
	fs.writeFileSync(msgsFailFlag, '')
	assert.strictEqual(
		fetchChannelHistory(config, 'chan-hist-1', { seckey: agent.seckey, authTag: agent.authTag }),
		null,
	)
})

test('isEmptyThread', async () => {
	assert.strictEqual(await isEmptyThread({ messages: async () => [] }), true)
	assert.strictEqual(
		await isEmptyThread({
			messages: async () => [{ role: 'user', id: 1, content: [{ type: 'text', text: 'hi' }] }],
		}),
		false,
	)
	assert.strictEqual(
		await isEmptyThread({
			messages: async () => {
				throw new Error('unavailable')
			},
		}),
		false,
	)
})
