// Run with a local pinned guest image and an empty output directory.
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {createReadStream, copyFileSync, mkdirSync, readFileSync, realpathSync, writeFileSync} from 'node:fs';
import {join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

assert.equal(process.argv.length, 4, 'usage: node scripts/pool_linux_stage.mjs IMAGE NEW_OUTPUT_DIRECTORY');
const root = fileURLToPath(new URL('../', import.meta.url));
const pin = JSON.parse(readFileSync(join(root, 'audit/pool-linux-target.json')));
const image = realpathSync(process.argv[2]);
const out = resolve(process.argv[3]);
const seed = join(out, 'seed');
async function digest(file) {
    const sha = createHash('sha256');
    for await (const chunk of createReadStream(file)) sha.update(chunk);
    return sha.digest('hex');
}
assert.equal(await digest(image), pin.guest.image_sha256, 'guest image');
const version = execFileSync('rustc', ['+' + pin.rust_release, '-vV'], {encoding:'utf8'});
assert(version.split('\n').includes('commit-hash: ' + pin.rust_commit));
const build = execFileSync('cargo', ['+' + pin.rust_release, 'test', '--offline', '--locked',
    '--manifest-path', 'server/Cargo.toml', '--lib', '--target', pin.target, '--no-run', '--message-format=json'],
    {cwd:root, encoding:'utf8', stdio:['ignore','pipe','inherit'], maxBuffer:16 << 20});
const artifacts = build.trim().split('\n').map(s => JSON.parse(s)).filter(a =>
    a.reason === 'compiler-artifact' && a.target.name === 'pathward_server' && a.executable);
assert.equal(artifacts.length, 1);
mkdirSync(out, {mode:0o700});
mkdirSync(seed, {mode:0o700});
copyFileSync(artifacts[0].executable, join(seed, 'pool-tests'));
copyFileSync(join(root,'scripts/pool_linux_guest.sh'), join(seed,'run'));
function file(name, contents) { writeFileSync(join(seed, name), contents + '\n'); }
file('release', pin.guest.release);
file('version-signature', pin.guest.version_signature);
file('kernel.sha256', pin.guest.kernel_sha256 + '  /boot/vmlinuz-' + pin.guest.release);
file('binary.sha256', await digest(join(seed,'pool-tests')) + '  pool-tests');
file('meta-data', 'instance-id: pool-linux-refinement\nlocal-hostname: pool-lab');
file('network-config', 'version: 2\nethernets: {}');
file('user-data', '#cloud-config\npackage_update: false\npackage_upgrade: false\nruncmd:\n' +
    '  - ["/bin/sh", "-c", "mkdir -p /mnt/pool-lab && mount -o ro /dev/sr0 /mnt/pool-lab && /bin/sh /mnt/pool-lab/run >/dev/ttyS0 2>&1; systemctl poweroff"]');
const run = (bin,args, opts={}) => execFileSync(bin,args,{cwd:out,stdio:'inherit',...opts});
run('xorriso',['-as','mkisofs','-quiet','-o','seed.iso','-V','cidata','-J','-r','seed']);
run('qemu-img',['create','-q','-f','qcow2','-F','qcow2','-b',image,'overlay.qcow2']);
run('qemu-system-x86_64',['-machine','pc','-accel','tcg,thread=multi','-m','1024','-smp','2',
    '-display','none','-monitor','none','-serial','file:serial.log','-nic','none','-no-reboot',
    '-rtc','base=utc,clock=host','-smbios','type=1,product=PathWardPoolLab',
    '-drive','file=overlay.qcow2,format=qcow2,if=virtio,cache=none',
    '-drive','file=seed.iso,format=raw,media=cdrom,readonly=on'],{timeout:600000,killSignal:'SIGKILL'});
assert(readFileSync(join(out,'serial.log'),'utf8').split(/\r?\n/).includes('POOL_LINUX_REFINEMENT_PASSED'),
    'guest checks failed; see ' + join(out,'serial.log'));
console.log('POOL_LINUX_REFINEMENT_PASSED',join(out,'serial.log'));
