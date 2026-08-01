import assert from 'node:assert'
import { test } from 'node:test'
import {
	bech32Encode,
	extractAssistantText,
	extractMentionTokens,
	sanitizeMentions,
	usernameSlug,
	generateKeypair,
	getPublicKey,
	mintOwnerAttestation,
	normalizePublicKey,
	normalizeSecretKey,
	schnorrSign,
	schnorrVerify,
	sha256,
	slugify,
	truncate,
	verifyOwnerAttestation,
} from '../buzz.ts'

// BIP-340 official test vectors (index 0-2 from bip-0340/test-vectors.csv)
const bip340Vectors = [
	{
		seckey: '0000000000000000000000000000000000000000000000000000000000000003',
		pubkey: 'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9',
		aux: '0000000000000000000000000000000000000000000000000000000000000000',
		msg: '0000000000000000000000000000000000000000000000000000000000000000',
		sig: 'e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0',
	},
	{
		seckey: 'b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef',
		pubkey: 'dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659',
		aux: '0000000000000000000000000000000000000000000000000000000000000001',
		msg: '243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89',
		sig: '6896bd60eeae296db48a229ff71dfe071bde413e6d43f917dc8dcf8c78de33418906d11ac976abccb20b091292bff4ea897efcb639ea871cfa95f6de339e4b0a',
	},
	{
		seckey: 'c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b14e5c9',
		pubkey: 'dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8',
		aux: 'c87aa53824b4d7ae2eb035a2b5bbbccc080e76cdc6d1692c4b0b62d798e6d906',
		msg: '7e2d58d8b3bcdf1abadec7829054f90dda9805aab56c77333024b9d0a508b75c',
		sig: '5831aaeed7b44bb74e5eab94ba9d4294c49bcf2a60728d8b4c200f50dd313c1bab745879a5ad954a72c45a91c3a51d3c7adea98d82f8481e0e1e03674a6f3fb7',
	},
]

test('BIP-340 pubkey derivation', () => {
	for (const v of bip340Vectors) {
		assert.strictEqual(getPublicKey(v.seckey), v.pubkey)
	}
})

test('BIP-340 signing with fixed aux', () => {
	for (const v of bip340Vectors) {
		const sig = schnorrSign(v.msg, v.seckey, Buffer.from(v.aux, 'hex'))
		assert.strictEqual(sig, v.sig)
	}
})

test('BIP-340 verification', () => {
	for (const v of bip340Vectors) {
		assert.ok(schnorrVerify(v.msg, v.pubkey, v.sig))
		const bad = v.sig.slice(0, 126) + (v.sig.slice(126) === '00' ? '01' : '00')
		assert.ok(!schnorrVerify(v.msg, v.pubkey, bad))
	}
})

// NIP-OA test vector from the Buzz protocol spec (docs/nips/NIP-OA.md)
test('NIP-OA test vector', () => {
	const agentPubkey = 'c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'
	const conditions = 'kind=1&created_at<1713957000'
	const preimage = `nostr:agent-auth:${agentPubkey}:${conditions}`
	assert.strictEqual(
		sha256(Buffer.from(preimage, 'utf8')).toString('hex'),
		'08cdecd55af4c28d3801fd69615dcf5cc04fab3bc134b38a840bf157197069a6',
	)
	const tag = [
		'auth',
		'79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
		conditions,
		'8b7df2575caf0a108374f8471722b233c53f9ff827a8b0f91861966c3b9dd5cb2e189eae9f49d72187674c2f5bd244145e10ff86c9f257ffe65a1ee5f108b369',
	]
	assert.ok(verifyOwnerAttestation(tag, agentPubkey))
	assert.ok(!verifyOwnerAttestation(tag, tag[1])) // self-attestation rejected
})

test('mint + verify round trip', () => {
	const owner = generateKeypair()
	const agent = generateKeypair()
	const tag = mintOwnerAttestation(owner.seckey, agent.pubkey, '')
	assert.strictEqual(tag[1], owner.pubkey)
	assert.ok(verifyOwnerAttestation(tag, agent.pubkey))
	assert.ok(!verifyOwnerAttestation(tag, owner.pubkey))
})

test('bech32 nsec/npub round trip', () => {
	const kp = generateKeypair()
	const nsec = bech32Encode('nsec', Buffer.from(kp.seckey, 'hex'))
	const npub = bech32Encode('npub', Buffer.from(kp.pubkey, 'hex'))
	assert.strictEqual(normalizeSecretKey(nsec), kp.seckey)
	assert.strictEqual(normalizePublicKey(npub), kp.pubkey)
	assert.strictEqual(normalizeSecretKey(kp.seckey.toUpperCase()), kp.seckey)
})

test('slugify + truncate', () => {
	assert.strictEqual(slugify('Fix the auth bug in login.ts!'), 'fix-the-auth-bug-in-login-ts')
	assert.strictEqual(slugify('   '), slugify('   ')) // stable fallback shape
	assert.ok(slugify('').startsWith('thread-'))
	assert.strictEqual(truncate('short'), 'short')
	assert.ok(truncate('x'.repeat(9000)).includes('[truncated, 1000 more chars]'))
})

test('extractAssistantText collects text blocks across the turn', () => {
	const messages = [
		{ role: 'user' as const, id: 1, content: [{ type: 'text' as const, text: 'do it' }] },
		{
			role: 'assistant' as const,
			id: 2,
			content: [
				{ type: 'thinking' as const, thinking: 'hmm' },
				{ type: 'text' as const, text: 'Working on it.' },
				{ type: 'tool_use' as const, id: 't1', name: 'Bash', input: {} },
			],
		},
		{
			role: 'assistant' as const,
			id: 3,
			content: [{ type: 'text' as const, text: 'Done: all tests pass.' }],
		},
	]
	assert.strictEqual(extractAssistantText(messages), 'Working on it.\n\nDone: all tests pass.')
	assert.strictEqual(extractAssistantText([messages[0]]), '')
})

test('usernameSlug', () => {
	assert.strictEqual(usernameSlug('joah'), 'joah')
	assert.strictEqual(usernameSlug('Joah Gerstenberg'), 'joah-gerstenberg')
	assert.strictEqual(usernameSlug('amp (local)'), 'amp-local')
	assert.strictEqual(usernameSlug('  @!#$  '), '')
	assert.strictEqual(usernameSlug(''), '')
	// stays within 24 chars and never ends with a dash
	const long = usernameSlug('a'.repeat(23) + ' b' + 'c'.repeat(30))
	assert.ok(long.length <= 24)
	assert.ok(!long.endsWith('-'))
})

test('extractMentionTokens', () => {
	assert.deepStrictEqual(extractMentionTokens('hey @joah, look at @code-review'), [
		'joah',
		'code-review',
	])
	assert.deepStrictEqual(extractMentionTokens('email me@example.com'), [])
	assert.deepStrictEqual(extractMentionTokens('(@fizz) and @fizz again'), ['fizz'])
	assert.deepStrictEqual(extractMentionTokens('no mentions here'), [])
	assert.deepStrictEqual(extractMentionTokens('@a.b_c-d rocks'), ['a.b_c-d'])
	// the buzz CLI treats even non-name @tokens as mentions — extract them too
	assert.deepStrictEqual(extractMentionTokens('testing @-tags here'), ['-tags'])
})

test('sanitizeMentions neutralizes only the given tokens', () => {
	const out = sanitizeMentions('cc @joah and @fizz about @joah', ['joah'])
	assert.strictEqual(out, 'cc @\u200bjoah and @fizz about @\u200bjoah')
	// regex metacharacters in a token must not break sanitization
	const weird = sanitizeMentions('ping @a.b_c-d now', ['a.b_c-d'])
	assert.strictEqual(weird, 'ping @\u200ba.b_c-d now')
	// token as substring of a longer handle is untouched
	assert.strictEqual(sanitizeMentions('see @joahg', ['joah']), 'see @joahg')
})

test('formatIncoming + INCOMING_RE round trip', async () => {
	const { formatIncoming, INCOMING_RE } = await import('../buzz.ts')
	const m = {
		id: 'e1',
		pubkey: 'p1',
		author: 'amp (BLK...)',
		content: 'hey there\nsecond line',
		created_at: 1,
		mentions_agent: false,
	}
	const text = formatIncoming(m)
	assert.strictEqual(text, '\u200bamp (BLK...): hey there\nsecond line')
	assert.ok(INCOMING_RE.test(text))
	// older [buzz]-prefixed shape must still be recognized
	assert.ok(INCOMING_RE.test('[buzz] amp (BLK...): hey there'))
	// older 💬-prefixed shapes must still be recognized
	assert.ok(INCOMING_RE.test('💬 amp (BLK...): hey there'))
	assert.ok(INCOMING_RE.test('💬 joah in #joah--fix-bug: older message'))
	// ordinary prompts must not match the marker
	assert.ok(!INCOMING_RE.test('fix the bug in login.ts'))
	assert.ok(!INCOMING_RE.test('💬 emoji but not the shape'))
	assert.ok(!INCOMING_RE.test('[buzz] emoji but not the shape'))
})
