import assert from 'node:assert/strict';
import {spawn,execFileSync} from 'node:child_process';
import {createPublicKey, randomBytes, verify} from 'node:crypto';
import {once} from 'node:events';
import {copyFileSync,readFileSync} from 'node:fs';
import {join} from 'node:path';
import {createInterface} from 'node:readline';
import {connect,resumeAtConsole,vmUuid} from './pool_delegates_host.mjs';
import {hash} from './pool_reconcile_host.mjs';

async function bridge(port,qmp,guest,target) {
    const peer=await connect(port,guest);
    const greeting=await new Promise((resolve,reject)=>{
        let input='';
        function data(bytes) {
            input+=bytes.toString('ascii');
            if(!'OPEN\n'.startsWith(input)) return reject(Error('invalid serial greeting'));
            if(input==='OPEN\n') {peer.off('data',data);resolve(input);}
        }
        peer.on('data',data);
        peer.once('close',()=>reject(Error('guest closed before serial greeting')));
        peer.once('error',reject);
    });
    assert.equal(greeting,'OPEN\n');
    const monitor=await connect(qmp,target);
    peer.pipe(monitor).pipe(peer);
    peer.once('close',()=>monitor.destroy());
    monitor.once('close',()=>peer.destroy());
}

export async function witnessBoots(machine,out) {
    const path=name=>join(out,name);
    const id=randomBytes(32).toString('hex');
    let publicKey,baseline,signatureChecked=false;
    execFileSync('qemu-img',['create','-q','-f','raw',path('authority.raw'),'32M']);
    const targetArgs=['-machine','pc','-accel','tcg','-m','48','-display','none','-serial','none','-monitor','none','-nic','none','-uuid',vmUuid];
    for(const name of ['command','events','console','trace']) targetArgs.push('-qmp','unix:'+path(name)+',server=on,wait=off');
    const target=spawn('qemu-system-x86_64',targetArgs,{cwd:out,stdio:'inherit'});
    const targetDone=once(target,'close');
    let trace;
    try {
        trace=await connect(path('trace'),target);
        const summary={STOP:0,RESUME:0};
        const traces=createInterface({input:trace})[Symbol.asyncIterator]();
        assert(JSON.parse((await traces.next()).value).QMP);
        trace.write('{"execute":"qmp_capabilities","id":1}\n');
        assert.equal(JSON.parse((await traces.next()).value).id,1);
        const observed=(async()=>{
            for await(const line of traces) {
                const v=JSON.parse(line);
                if(v.event && Object.hasOwn(summary,v.event)) summary[v.event]++;
                if(v.id===2) { assert.equal(v.return.running,true);return; }
            }
            throw Error('trace ended before barrier');
        })();
        // Attach a handler immediately, including if a guest boot fails early.
        observed.catch(()=>{});
        for(const [i,phase] of ['baseline','submit','restored'].entries()) {
            const image=path('overlay.qcow2'),previous=path('witness-before.qcow2');
            if(i===2) {
                assert.notEqual(await hash(image),baseline);
                const retained=await hash(path('authority.raw'));
                copyFileSync(previous,image);assert.equal(await hash(image),baseline);
                assert.equal(await hash(path('authority.raw')),retained);
                console.log('WITNESS_ROOT_ROLLBACK restored_sha256=%s retained_authority_sha256=%s',baseline,retained);
            }
            const serial='witness-'+i+'.log';
            const args=[...machine,'-serial','file:'+serial,'-drive','file=overlay.qcow2,format=qcow2,if=none,id=rootdisk,cache=none',
                '-device','virtio-blk-pci,drive=rootdisk,addr=0x5,bootindex=1',
                '-drive','file=authority.raw,format=raw,if=none,id=auth,cache=none','-device','virtio-blk-pci,drive=auth,addr=0x6,serial=pw-witness-journal',
                '-device','virtio-serial-pci'];
            const channel=(label,dev)=>{
                const sock=path(label+i);
                args.push('-chardev','socket,id='+label+',path='+sock+',server=on,wait=off','-device','virtserialport,chardev='+label+',name='+dev);
                return sock;
            };
            const control=channel('ctl','org.pathward.witness.lab');
            const ports=i===1?['command','events'].map(name=>[channel('v'+name,'org.pathward.qmp.'+name),path(name)]):[];
            const guest=spawn('qemu-system-x86_64',args,{cwd:out,stdio:'inherit'});
            const closed=once(guest,'close'),timer=setTimeout(()=>guest.kill('SIGKILL'),600000);
            let sock;
            try {
                const bridged=Promise.all(ports.map(([p,q])=>bridge(p,q,guest,target)));
                bridged.catch(()=>{});
                sock=await connect(control,guest);
                for await(const line of createInterface({input:sock,crlfDelay:Infinity})) {
                    if(line==='phase') {sock.write([phase,id,vmUuid].join(' ')+'\n');continue;}
                    if(i===0 && /^KEY [0-9a-f]{64}$/.test(line)) {
                        publicKey=createPublicKey({key:Buffer.from('302a300506032b6570032100'+line.slice(4),'hex'),type:'spki',format:'der'});continue;
                    }
                    if(i===1 && line==='resume') {await resumeAtConsole(path('console'));continue;}
                    const m=/^COMPLETED ([0-9a-f]{64}) ([0-9a-f]{128})$/.exec(line);
                    assert(i===2 && m && m[1]===id && publicKey);
                    assert(verify(null,Buffer.from('PathWard independently observed QEMU resume v2\n'+vmUuid+'\n'+id+'\n'),publicKey,Buffer.from(m[2],'hex')));
                    signatureChecked=true;
                }
                await bridged;assert.equal((await closed)[0],0);
                const result=readFileSync(path(serial),'utf8').replaceAll('\r','').split('\n');
                assert(result.includes(['WITNESS_BASELINE','WITNESS_COMPLETED_BEFORE_RESTORE','WITNESS_ROOT_RESTORED local_claim_absent=true signed_original_recovered=true'][i]),'see '+serial);
                if(i) assert(result.includes('WITNESS_EXIT=0'));
                if(!i) {copyFileSync(image,previous);baseline=await hash(previous);}
            } finally {
                clearTimeout(timer);sock?.destroy();if(guest.exitCode===null) guest.kill('SIGKILL');
            }
        }
        trace.write('{"execute":"query-status","id":2}\n');await observed;
        assert(signatureChecked);assert.deepEqual(summary,{STOP:1,RESUME:1});
        console.log('WITNESS_LINUX_ROLLBACK whole_root_restored=true signature_verified=true qmp_stops=1 qmp_resumes=1');
    } finally {
        trace?.destroy();target.kill();await targetDone;
    }
}
