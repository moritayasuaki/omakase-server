// Run an ignored Rust test fixture on loopback. Only public test certificates cross this pipe.
import { execFileSync, spawn } from 'node:child_process';
import crypto from 'node:crypto';
import dgram from 'node:dgram';
import { once } from 'node:events';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

const [binary, reportPath] = process.argv.slice(2);
if (!binary || !reportPath) throw Error('Usage: node scripts/transport_benchmark.mjs TEST_BINARY NEW_REPORT');
const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'omakase-throughput-'));
const report = { bytes: 818100, clients: 24, results: [] };
const body = Buffer.alloc(report.bytes);
for (let i = 0; i < body.length; ++i) body[i] = i % 251;
const digest = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const expected = digest(body);
const ready = Buffer.from('ready');

// Each client gets a distinct UDP path. Delay affects data and acknowledgements in both directions.
// Count loss deterministically and bound outstanding datagrams in the fixture itself.
async function link(target, delayMs, dropEvery) {
  const front = dgram.createSocket('udp4');
  const peers = new Map();
  const timers = new Set();
  const counts = { datagrams: 0, dropped: 0, peakQueued: 0 };
  let failure;
  function forward(bytes, socket, port) {
    counts.datagrams++;
    if (dropEvery && counts.datagrams % dropEvery === 0) { counts.dropped++; return; }
    if (timers.size >= 16384) { failure ??= Error('relay queue limit'); return; }
    const timer = setTimeout(() => {
      timers.delete(timer);
      socket.send(bytes, port, '127.0.0.1', err => { if (err) failure ??= err; });
    }, delayMs);
    timers.add(timer);
    counts.peakQueued = Math.max(counts.peakQueued, timers.size);
  }
  front.on('message', (packet, peer) => {
    let back = peers.get(peer.port);
    if (!back) {
      if (peers.size >= 128) { failure ??= Error('relay peer limit'); return; }
      back = dgram.createSocket('udp4');
      back.on('error', err => { failure ??= err; });
      back.on('message', (bytes, source) => {
        if (source.port === target && source.address === '127.0.0.1') forward(bytes, front, peer.port);
      });
      back.bind(0, '127.0.0.1');
      peers.set(peer.port, back);
    }
    forward(packet, back, target);
  });
  front.bind(0, '127.0.0.1');
  await once(front, 'listening');
  return { port: front.address().port, counts, close() {
    for (const timer of timers) clearTimeout(timer);
    for (const back of peers.values()) back.close();
    front.close();
    if (failure) throw failure;
  } };
}

async function transfer(port, certificate, asset, protocol = '3') {
  const args = ['--noproxy', '*', '--silent', '--show-error', '--fail', '--max-time', '45',
    protocol === '3' ? '--http3-only' : '--http2', '--cacert', certificate,
    '--connect-to', 'app.example:443:127.0.0.1:' + port,
    '--write-out', '%{stderr}%{response_code} %{http_version} %{num_connects} %{time_starttransfer} %{time_total}\\n',
    '-o', os.devNull, 'https://app.example/ready', '-o', '-', 'https://app.example/' + (asset ? 'asset' : 'ready')];
  const proc = spawn('curl', args, { stdio: ['ignore','pipe','pipe'] });
  const hash = crypto.createHash('sha256');
  let bytes = 0, stats = '';
  proc.stdout.on('data', chunk => { bytes += chunk.length; hash.update(chunk); });
  proc.stderr.on('data', chunk => { stats = (stats + chunk).slice(-4096); });
  const [code] = await once(proc, 'close');
  const lines = stats.trim().split('\n').map(line => line.trim().split(/\s+/));
  if (code !== 0 || lines.length !== 2 || lines.some(row => row[0] !== '200' || row[1] !== protocol)
      || lines[0][2] !== '1' || lines[1][2] !== '0' || bytes !== (asset ? body.length : ready.length)
      || hash.digest('hex') !== (asset ? expected : digest(ready))) throw Error('Transfer failed: ' + stats);
  return { firstByteMs: Number(lines[1][3])*1000, totalMs: Number(lines[1][4])*1000 };
}

async function phaseTotals(port, protocol, expectedCount) {
  const deadline = Date.now() + 3000;
  do {
    const response = await fetch('http://127.0.0.1:' + port + '/metrics', {
      headers: { Connection: 'close' }, signal: AbortSignal.timeout(3000)
    });
    if (!response.ok) throw Error('Monitor returned ' + response.status);
    const lines = (await response.text()).split('\n');
    const totals = {};
    for (const phase of ['prepare', 'submit']) {
      for (const field of ['sum', 'count']) {
        const prefix = 'pathward_response_phase_microseconds_' + field
          + '{protocol="' + protocol + '",phase="' + phase + '"} ';
        const line = lines.find(value => value.startsWith(prefix));
        if (!line) throw Error('Missing monitor value ' + prefix);
        totals[phase + '_' + field] = Number(line.slice(prefix.length));
      }
    }
    if (totals.prepare_count === expectedCount && totals.submit_count === expectedCount) return totals;
    await new Promise(resolve => setTimeout(resolve, 10));
  } while (Date.now() < deadline);
  throw Error('Expected ' + expectedCount + ' completed ' + protocol + ' responses in both phases');
}

async function trial(window) {
  const proc = spawn(binary, ['--exact','browser_fixture::transport_benchmark_fixture','--ignored','--nocapture'],
    { env: { ...process.env, OMAKASE_TEST_SEND_WINDOW: window }, stdio: ['pipe','pipe','pipe'] });
  const exited = once(proc, 'close');
  const timer = setTimeout(() => proc.kill(), 240000);
  try {
    let log = '';
    for await (const bytes of proc.stdout.iterator({ destroyOnReturn: false })) {
      log += bytes;
      if (log.includes('-----END CERTIFICATE-----')) break;
      if (log.length > 8192) throw Error('Unexpected fixture output');
    }
    const pem = log.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/);
    const match = log.match(/BENCH_PORT=(\d+)/);
    const monitorMatch = log.match(/MONITOR_PORT=(\d+)/);
    if (!pem || !match || !monitorMatch) throw Error('Fixture startup failed: ' + log);
    const port = Number(match[1]);
    const monitorPort = Number(monitorMatch[1]);
    const ca = path.join(directory, window + '.pem');
    await fs.writeFile(ca, pem[0] + '\n', {mode:0o600});
    const baseline = await transfer(port, ca, true, '2');
    await phaseTotals(monitorPort, 'h2', 2);
    let totals = await phaseTotals(monitorPort, 'h3', 0);
    for (const dropEvery of [0, 1000]) {
      const relay = await link(port, 75, dropEvery);
      let peakRssKiB = 0;
      const monitor = setInterval(() => {
        if (proc.exitCode === null) {
          const sample = Number(execFileSync('ps', ['-o','rss=','-p',String(proc.pid)], {encoding:'utf8'}));
          peakRssKiB = Math.max(peakRssKiB, sample);
        }
      }, 500);
      try {
        const samples = [];
        for (let i = 0; i < 3; i++) {
          const timing = await transfer(relay.port, ca, true);
          const after = await phaseTotals(monitorPort, 'h3', totals.submit_count + 2);
          samples.push({
            ...timing,
            pairPrepareMs: (after.prepare_sum - totals.prepare_sum) / 1000,
            pairSubmitMs: (after.submit_sum - totals.submit_sum) / 1000
          });
          totals = after;
        }
        const waves = [];
        for (let i=0; i<2; i++) {
          const wave = await Promise.allSettled(Array.from({length:report.clients}, () => transfer(relay.port, ca, i === 1)));
          for (const result of wave) if (result.status !== 'fulfilled') throw result.reason;
          waves.push(wave.map(result => result.value.totalMs));
          totals = await phaseTotals(monitorPort, 'h3', totals.submit_count + 2 * report.clients);
        }
        report.results.push({window, rttMs:150, dropEvery, h2Loopback:baseline, samples, reconnectMs:waves, peakRssKiB, relay:relay.counts});
      } finally { clearInterval(monitor); relay.close(); }
    }
  } finally {
    proc.stdin.end('stop\n');
    const [code] = await exited;
    clearTimeout(timer);
    if (code !== 0) throw Error('Fixture exited ' + code);
  }
}
try {
  for (const window of ['128KiB', '256KiB', '512KiB']) await trial(window);
  await fs.writeFile(reportPath, JSON.stringify(report,null,2)+'\n',{flag:'wx'});
} finally { await fs.rm(directory,{recursive:true,force:true}); }
