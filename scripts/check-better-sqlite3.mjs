// Does SqliteStore actually run on better-sqlite3?
//
// The unit tests exercise it on node:sqlite. VIOLINET OS hands it better-sqlite3.
// The `Db` interface claims to be the intersection of the two, and an interface
// that only ever meets one implementation is a guess -- this runs the real
// store, the real gate, and the real SQL against the other driver.
//
// better-sqlite3 is a native module built for Electron, so this needs the
// ELECTRON_RUN_AS_NODE path or a matching ABI. It is a check you run, not part
// of `npm test`, because it depends on violet-dev having installed.
//
//   node scripts/check-better-sqlite3.mjs

import { createRequire } from 'node:module';
import { randomUUID } from 'node:crypto';
import { SqliteStore } from '../src/core/store.ts';
import { Gate } from '../src/core/gate.ts';

const require = createRequire(process.env.BASHME_HOST_PACKAGE_JSON ?? import.meta.url);
const Database = require('better-sqlite3');

const ROOT = 'C:\\work\\project';
const db = new Database(':memory:');
const store = new SqliteStore(db);

const fail = (msg) => {
  console.error(`FAIL: ${msg}`);
  process.exitCode = 1;
};
const eq = (actual, expected, msg) => {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail(`${msg} — got ${JSON.stringify(actual)}, expected ${JSON.stringify(expected)}`);
  }
};

store.upsertRule({
  id: 'r1',
  enabled: true,
  originatorId: 'violet-os:agent-tools',
  kind: 'shell',
  prefixes: ['npm run build'],
  createdAt: new Date().toISOString(),
  matchCount: 0,
});
store.recordMatch('r1');
eq(store.listRules()[0]?.matchCount, 1, 'match count increments on better-sqlite3');
eq(store.listRules()[0]?.prefixes, ['npm run build'], 'prefixes round-trip on better-sqlite3');

store.writeToggle('enabled', true);
store.writeToggle('rulesEnabled', true);
eq(
  store.readToggles(),
  { enabled: true, rulesEnabled: true, devicesEnabled: false },
  'toggles round-trip (ON CONFLICT upsert works on better-sqlite3)',
);

let presented = null;
const gate = new Gate(
  { ...store.readToggles(), devicesEnabled: false, workspaceRoot: ROOT, timeoutMs: 80 },
  {
    audit: { append: (r) => store.appendAudit(r) },
    rules: { list: () => store.listRules(), recordMatch: (id) => store.recordMatch(id) },
    present: (p) => {
      presented = p;
    },
  },
);

const mk = (command) => ({
  id: randomUUID(),
  kind: 'shell',
  command,
  cwd: ROOT,
  originator: { id: 'violet-os:agent-tools', label: 'Agent tools' },
  requestedAt: new Date().toISOString(),
});

eq(await gate.request(mk('npm run build')), true, 'a matching rule auto-approves');
eq(presented, null, 'an auto-approved request must not have been presented');

eq(await gate.request(mk('rm -rf /')), false, 'rm -rf denies');
eq(presented?.verdict?.hardBlocked, true, 'rm -rf was hard-blocked and presented');

const rows = store.recentAudit().map((r) => r.resolution.type).sort();
eq(rows, ['approved-by-rule', 'timeout'], 'both outcomes were audited');

if (!process.exitCode) console.log('better-sqlite3 OK — store and gate behave identically on both drivers');
