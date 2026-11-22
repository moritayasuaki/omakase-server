import assert from 'node:assert/strict';
import {execFileSync, spawn} from 'node:child_process';
import {once} from 'node:events';
import {readFileSync} from 'node:fs';
import {createConnection} from 'node:net';
import {join} from 'node:path';
import {createInterface} from 'node:readline';
import {setTimeout as delay} from 'node:timers/promises';

const vmUuid='3acefc01-45b6-4e29-88cb-119ccc6c25c3';
export function prepareProvider(root,out) {
    const args=['+1.98.1','build','--offline','--locked','--manifest-path','admin/Cargo.toml','--bin','pathward-qmp-sleep','--message-format=json'];
    const lines=execFileSync('cargo',args,{cwd:root,encoding:'utf8',maxBuffer:16<<20}).trim().split('\n');
    const bin=lines.map(s=>JSON.parse(s)).find(e=>e.target?.name==='pathward-qmp-sleep' && e.executable)?.executable;
    assert(bin);
    const dir=join(out,'witness');
    const key=execFileSync(bin,['keygen',dir,vmUuid],{encoding:'utf8'}).trim();
    assert.match(key,/^[a-f0-9]{64}$/);
    return {bin,dir,publicLine:vmUuid+' '+key};
}

async function connect(path,guest) {
    for(let i=0;i<300 && guest.exitCode===null;i++) {
        const sock=createConnection(path);
        try { await once(sock,'connect'); return sock; } catch { sock.destroy(); await delay(50); }
    }
    throw Error('guest control port unavailable');
}

// Disposable guest console recovery after its witness exits while paused.
// This monitor has no signing authority and never returns a receipt.
async function resumeAtConsole(qmp) {
    const socket=createConnection(qmp);
    socket.setTimeout(10000,()=>socket.destroy(Error('console timeout')));
    const lines=createInterface({input:socket})[Symbol.asyncIterator]();
    const next=async()=>JSON.parse((await lines.next()).value);
    let id=0;
    async function call(execute) {
        socket.write(JSON.stringify({execute,id:++id})+'\n');
        for(let n=0;n<128;n++) {
            const v=await next();
            if(v.event) continue;
            assert.equal(v.id,id);assert(Object.hasOwn(v,'return'));
            return v.return;
        }
        throw Error('too many console events');
    }
    try {
        assert((await next()).QMP);
        await call('qmp_capabilities');
        assert.equal((await call('query-uuid')).UUID,vmUuid);
        assert.equal((await call('query-status')).status,'paused');
        await call('cont');
        assert.equal((await call('query-status')).running,true);
    } finally { socket.destroy(); }
}

async function serve(sock,provider,qmp,trial) {
    const channel=createInterface({input:sock,crlfDelay:Infinity});
    for await (const line of channel) {
        const match=/^(pause|receipt|lose-witness) ([0-9a-f]{64})$/.exec(line);
        assert(match,'invalid fixture request');
        const [,op,ticket]=match;
        const {bin,dir}=provider;
        if(op!=='receipt') {
            const witness=spawn(bin,['pause',dir,qmp,ticket],{stdio:['pipe','pipe','inherit']});
            const done=once(witness,'close');
            try {
                const output=createInterface({input:witness.stdout})[Symbol.asyncIterator]();
                assert.equal((await output.next()).value,'PAUSED '+ticket);
                assert.throws(()=>execFileSync(bin,['receipt',dir,ticket],{stdio:'ignore'}));
                if(op==='lose-witness') {
                    witness.stdin.end();
                    assert.equal((await done)[0],1);
                    await resumeAtConsole(qmp);
                    assert.throws(()=>execFileSync(bin,['receipt',dir,ticket],{stdio:'ignore'}));
                    assert.throws(()=>execFileSync(bin,['pause',dir,qmp,ticket],{input:'',stdio:'ignore'}));
                    sock.write('UNCONFIRMED '+ticket+'\n');
                    continue;
                }
                const start=process.hrtime.bigint();
                await delay(5500);
                const held=process.hrtime.bigint()-start;
                assert(held>=5000000000n);
                witness.stdin.end('resume '+ticket+'\n');
                const completed=(await output.next()).value;
                assert(new RegExp('^COMPLETED '+ticket+' [0-9a-f]{128}$').test(completed));
                assert.equal((await done)[0],0);
                assert.throws(()=>execFileSync(bin,['pause',dir,qmp,ticket],{input:'',stdio:'ignore'}));
                console.log('QMP_WITNESS boot=%d hold_ns=%s resume_confirmed=true duplicate_submission_denied=true',trial,held.toString());
                sock.write('WITNESSED '+ticket+'\n');
            } finally { if(witness.exitCode===null) witness.kill(); }
        } else {
            const receipt=execFileSync(bin,['receipt',dir,ticket],{encoding:'utf8'}).trim();
            assert(new RegExp('^COMPLETED '+ticket+' [0-9a-f]{128}$').test(receipt));
            sock.write(receipt+'\n');
        }
    }
}

export async function boots(machine,out,provider) {
    machine.push('-drive','file=overlay.qcow2,format=qcow2,if=virtio,cache=none','-uuid',vmUuid);
    for (const trial of [1,2]) {
        const serial='serial-'+trial+'.log';
        const channel=join(out,'channel'+trial);
        const qmp=join(out,'qmp'+trial);
        const guest=spawn('qemu-system-x86_64',[...machine,'-serial','file:'+serial,'-qmp','unix:'+qmp+',server=on,wait=off',
            '-device','virtio-serial-pci','-chardev','socket,id=deleg,path='+channel+',server=on,wait=off',
            '-device','virtserialport,chardev=deleg,name=org.pathward.delegations'],{cwd:out,stdio:'inherit'});
        const done=once(guest,'close');
        const timer=setTimeout(()=>guest.kill('SIGKILL'),600000);
        let sock;
        try {
            sock=await connect(channel,guest);
            const [,exit]=await Promise.all([serve(sock,provider,qmp,trial),done]);
            assert.equal(exit[0],0);
            const transcript=readFileSync(join(out,serial),'utf8').replaceAll('\r','').split('\n');
            assert(transcript.includes(trial===1?'DELEGATED_FIRST_POWEROFF':'POOL_DELEGATED_PASSED'),'see '+serial);
            if(trial===2) assert(transcript.includes('COLD_GUEST_EXIT=0'));
        } finally {
            clearTimeout(timer);sock?.destroy();
            if(guest.exitCode===null) guest.kill('SIGKILL');
        }
    }
    console.log('POOL_DELEGATED_PASSED',out);
}
