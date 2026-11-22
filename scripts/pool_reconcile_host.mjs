import assert from 'node:assert/strict';
import {execFileSync,spawn,spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {once} from 'node:events';
import {chmodSync,copyFileSync,cpSync,createReadStream,existsSync,mkdirSync,readFileSync,renameSync} from 'node:fs';
import {join} from 'node:path';
import {createInterface} from 'node:readline';
import {setTimeout as delay} from 'node:timers/promises';
import {connect,resumeAtConsole,vmUuid} from './pool_delegates_host.mjs';

function child(binary,args) {
    const process=spawn(binary,args,{stdio:['pipe','pipe','inherit']});
    return {process,done:once(process,'close'),lines:createInterface({input:process.stdout})[Symbol.asyncIterator]()};
}
export async function hash(file) {
    const h=createHash('sha256');
    for await(const bytes of createReadStream(file)) h.update(bytes);
    return h.digest('hex');
}

async function rejectTwin(out,bin) {
    const privateDir=join(out,'twin-authority'),mirror=join(out,'twin-submitter');
    mkdirSync(mirror,{mode:0o700});
    execFileSync(bin,['keygen',privateDir,vmUuid],{stdio:'ignore'});
    const ticket='8'.repeat(64);
    const sockets=['twin-a','twin-b'].map(n=>join(out,n)),machines=[];
    let observer;
    const closed=[];
    try {
        for(const sock of sockets) {
            const q=spawn('qemu-system-x86_64',['-machine','pc','-accel','tcg','-m','48','-display','none','-serial','none','-nic','none',
                '-monitor','none','-uuid',vmUuid,'-qmp','unix:'+sock+',server=on,wait=off'],{stdio:'inherit'});
            machines.push(q);closed.push(once(q,'close'));
            for(let i=0;i<150 && !existsSync(sock);i++) await delay(50);
            assert(existsSync(sock));
        }
        const old='7'.repeat(64);
        const lost=spawnSync(bin,['pause',privateDir,sockets[0],old],{input:'',encoding:'utf8',timeout:15000});
        assert.equal(lost.status,1);
        assert.equal(lost.stdout.trim(),'PAUSED '+old);
        await resumeAtConsole(sockets[0]);
        assert.throws(()=>execFileSync(bin,['observe',privateDir,sockets[0],old],{stdio:'pipe',timeout:10000}),/already spent/);
        assert.throws(()=>execFileSync(bin,['reconcile',privateDir,old],{stdio:'ignore'}));
        console.log('QMP_LEGACY_LOSS v2_observation_denied=true receipt_absent=true');
        observer=child(bin,['observe',privateDir,sockets[0],ticket]);
        assert.equal((await observer.lines.next()).value,'ARMED '+ticket);
        assert.throws(()=>execFileSync(bin,['pause-once',mirror,privateDir,sockets[1],ticket],{stdio:['ignore','pipe','pipe']}),/different emulator/);
        assert.throws(()=>execFileSync(bin,['reconcile',privateDir,ticket],{stdio:'ignore'}));
        console.log('QMP_TWIN same_uuid=true foreign_emulator_denied=true receipt_absent=true');
    } finally {
        if(observer) {observer.process.kill();await observer.done;}
        for(const q of machines) q.kill();
        await Promise.all(closed);
    }
}

export async function reconcileBoots(machine,out,{bin,dir}) {
    const mirror=join(out,'submitter'),backup=join(out,'submitter-before');
    mkdirSync(mirror,{mode:0o700});
    cpSync(mirror,backup,{recursive:true});
    chmodSync(backup,0o700);
    const run=(args)=>execFileSync(bin,args,{encoding:'utf8',stdio:['ignore','pipe','pipe']}).trim();
    const image=join(out,'overlay.qcow2'),snapshot=join(out,'root-before.qcow2');
    const guard=join(out,'guard.raw');
    execFileSync('qemu-img',['create','-q','-f','raw',guard,'32M']);
    let original,baselineHash;
    for(const [i,phase] of ['baseline','submit','restored'].entries()) {
        if(phase==='restored') {
            assert.notEqual(await hash(image),baselineHash);
            const retained=await hash(guard);
            copyFileSync(snapshot,image);
            assert.equal(await hash(image),baselineHash);
            assert.equal(await hash(guard),retained);
            console.log('GUEST_ROOT_ROLLBACK restored_sha256=%s retained_guard_sha256=%s',baselineHash,retained);
        }
        const serial='reconcile-'+i+'.log', channel=join(out,'ch'+i);
        const command=join(out,'q'+i),events=join(out,'e'+i);
        const guest=spawn('qemu-system-x86_64',[...machine,'-uuid',vmUuid,'-drive','file=overlay.qcow2,format=qcow2,if=none,id=rootdisk,cache=none',
            '-device','virtio-blk-pci,drive=rootdisk,addr=0x5,bootindex=1',
            '-drive','file=guard.raw,format=raw,if=none,id=guard,cache=none','-device','virtio-blk-pci,drive=guard,addr=0x6,serial=pathward-qmp-guard',
            '-serial','file:'+serial,'-qmp','unix:'+command+',server=on,wait=off','-qmp','unix:'+events+',server=on,wait=off',
            '-device','virtio-serial-pci','-chardev','socket,id=cmd,path='+channel+',server=on,wait=off',
            '-device','virtserialport,chardev=cmd,name=org.pathward.delegations'],{cwd:out,stdio:'inherit'});
        const done=once(guest,'close'),timer=setTimeout(()=>guest.kill('SIGKILL'),600000);
        let sock,observer,worker;
        try {
            sock=await connect(channel,guest);
            for await(const line of createInterface({input:sock,crlfDelay:Infinity})) {
                if(line==='phase') { sock.write(phase+'\n');continue; }
                if(line==='original') { assert.equal(phase,'restored');sock.write(original+'\n');continue; }
                const [,op,id]=/^(lose|ambiguous|receipt) ([a-f0-9]{64})$/.exec(line)??[];
                assert(id,'unknown guest command');
                if(op==='receipt') {
                    assert.equal(id,original);
                    const receipt=run(['reconcile',dir,id]);assert.match(receipt,new RegExp('^COMPLETED '+id+' [a-f0-9]{128}$'));
                    sock.write(receipt+'\n');continue;
                }
                observer=child(bin,['observe',dir,events,id]);
                assert.equal((await observer.lines.next()).value,'ARMED '+id);
                worker=child(bin,['pause-once',mirror,dir,command,id]);
                assert.equal((await worker.lines.next()).value,'PAUSED '+id);
                worker.process.kill('SIGKILL');
                assert.equal((await worker.done)[1],'SIGKILL'); worker=null;
                assert.throws(()=>run(['reconcile',dir,id]));
                if(op==='ambiguous') {
                    observer.process.kill('SIGKILL');assert.equal((await observer.done)[1],'SIGKILL');observer=null;
                } else {
                    original=id;
                    renameSync(mirror,mirror+'-after');
                    cpSync(backup,mirror,{recursive:true});
                    chmodSync(mirror,0o700);
                    assert.throws(()=>readFileSync(join(mirror,id+'.started')));
                    assert.throws(()=>run(['pause-once',mirror,dir,command,id]),/already spent/);
                }
                await resumeAtConsole(command);
                assert.throws(()=>run(['pause-once',mirror,dir,command,id]));
                if(observer) {
                    assert.equal((await observer.lines.next()).value,'OBSERVED '+id);
                    assert.equal((await observer.done)[0],0);observer=null;
                    assert.throws(()=>run(['observe',dir,events,id]));
                    const legacy=spawnSync(bin,['pause',dir,command,id],{input:'',encoding:'utf8',timeout:15000});
                    assert.equal(legacy.status,1);
                    assert.equal(legacy.stdout,'');
                    assert.match(legacy.stderr,/already spent/);
                    console.log('QMP_LEGACY_REPLAY original_claim_reused=true duplicate_stop_denied=true');
                    console.log('WITNESS_ROLLBACK killed_after_pause=true empty_mirror_restored=true duplicate_denied=true original_resume_observed=true');
                    sock.write('OBSERVED '+id+'\n');
                } else {
                    assert.throws(()=>run(['reconcile',dir,id]));
                    assert.throws(()=>run(['observe',dir,events,id]));
                    sock.write('UNCONFIRMED '+id+'\n');
                }
            }
            assert.equal((await done)[0],0);
            const transcript=readFileSync(join(out,serial),'utf8').replaceAll('\r','').split('\n');
            assert(transcript.includes(['RECONCILE_BASELINE','RECONCILE_SUBMITTED','POOL_RECONCILIATION_PASSED'][i]),'see '+serial);
            if(i) assert(transcript.includes('COLD_GUEST_EXIT=0'));
            if(!i) { copyFileSync(image,snapshot);baselineHash=await hash(snapshot); }
        } finally {
            clearTimeout(timer);sock?.destroy();worker?.process.kill();observer?.process.kill();
            if(guest.exitCode===null) guest.kill('SIGKILL');
        }
    }
    await rejectTwin(out,bin);
    console.log('POOL_RECONCILIATION_PASSED');
}
