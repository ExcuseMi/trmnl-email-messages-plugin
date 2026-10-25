// Run: node --test plugin/test
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const source = readFileSync(new URL("../src/transform.js", import.meta.url), "utf8");
const transform = new Function(`${source}; return transform;`)();
const shown = { data: { success: true, messages: [{ subject: "earlier" }] } };
const withPrevious = (payload) => ({ ...payload, trmnl: { previous_merge_variables: shown } });

test("fresh mail replaces the screen", () => {
  const out = transform(withPrevious({ success: true, messages: [{ subject: "new" }] }));
  assert.equal(out.data.messages[0].subject, "new");
});

for (const code of ["THROTTLED", "TIMEOUT", "CONNECTION"]) {
  test(`${code} keeps the previous mail`, () => {
    assert.deepEqual(transform(withPrevious({ success: false, code, error: "x" })), shown);
  });
}

test("a failed fetch (empty payload) keeps the previous mail", () => {
  assert.deepEqual(transform(withPrevious({})), shown);
});

test("a wrong password is shown, not hidden behind old mail", () => {
  const out = transform(withPrevious({ success: false, code: "AUTH_FAILED", error: "Authentication Failed" }));
  assert.equal(out.data.code, "AUTH_FAILED");
});

test("throttled without previous values (after Force Refresh) shows the message", () => {
  const out = transform({ success: false, code: "THROTTLED", error: "Refreshing too often", trmnl: { previous_merge_variables: {} } });
  assert.equal(out.data.error, "Refreshing too often");
});
