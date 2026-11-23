# Tracking delegated sleep work

A local sleep hook can return while a separate service is running or a hypervisor still owns a pause. A Linux pooled first write requires an awake boot fence, an empty systemd slot, an empty hypervisor slot and the usual fresh backend health. The two slots can overlap. A second registration for an occupied slot fails before submission. Health probes, fixed upstreams and continuation of an already dispatched request retain their existing behavior.

## Provision a pooled host

Before starting the upgraded pooled server, run `omakase-server sleep-delegate init-local` once as the host administrator. This also enables local systemd delegation. The command creates a root-owned ledger in `/var/lib/pathward-sleep-delegates` and binds its directory inode and random installation ID to `/etc/pathward-sleep-delegates.id`. Share both paths with every serving process, including private mount namespaces. Store the ledger on persistent local storage. Hypervisor enrollment supports ext4, XFS and Btrfs.

Upgrade every pooled server before enabling a delegating hook, then run `pool-preflight CONFIG --control-dir DIR` for each one. The F2 observation compares both inodes. An old server, missing ledger, inaccessible anchor or mismatched identity blocks readiness. Cold boot initializes only the ordinary boot fence. A missing persistent record keeps first writes closed. Provisioning preserves an existing registration and rejects a missing ledger with a retained anchor. With the single-witness protocol, keep both paths and the hypervisor witness store outside snapshot rollback.

## A separate systemd service

Install the shipped `deploy/pathward-delegated-sleep@.service` under `/etc/systemd/system/`, install the reviewed site-specific helper as `/usr/local/libexec/pathward-delegated-sleep` and run `systemctl daemon-reload`. The helper receives the ticket as its only argument. Its power work belongs to the instance cgroup. Further delegation needs its own registration. The originating hook invokes:

```sh
omakase-server sleep-delegate service-start
```

The command registers a fresh 256-bit ticket on disk before issuing one nonblocking start for `pathward-delegated-sleep@TICKET.service`. A pre-submission check validates the loaded template. If submission has an uncertain outcome, use `sleep-delegate status` to retrieve the ticket. In the host mount and cgroup namespaces, run:

```sh
omakase-server sleep-delegate service-check TICKET
```

The matching instance must have completed successfully in its original boot and clock domain. The check requires an exited oneshot retained by systemd, a valid invocation ID and exit timestamp, zero main/control PIDs, an empty job and an empty recursive cgroup. It reads the unit again after checking the cgroup. Both the start and completion checks reject additional lifecycle commands, including stop and reload hooks. After successful confirmation, the administrator can release the exited instance with `systemctl stop pathward-delegated-sleep@TICKET.service`. Use a fresh ticket for each job. Failed units, lost terminal evidence and a reboot before confirmation leave the slot closed. [systemd oneshot and RemainAfterExit](https://www.freedesktop.org/software/systemd/man/255/systemd.service.html) · [cgroup v2 population](https://docs.kernel.org/admin-guide/cgroup-v2.html#core-interface-files)

## A QEMU hypervisor with a single witness

Build the optional native witness with `cargo build --release --locked --manifest-path admin/Cargo.toml --bin omakase-qmp-sleep`. On the hypervisor host, create a private persistent directory for one VM and its new signing key. Configure QEMU with this explicit nonzero VM UUID and a private Unix QMP monitor. Use a private, trusted parent directory for the witness directory and monitor socket.

```sh
omakase-qmp-sleep keygen /private/provider-state VM_UUID
```

Install the printed Ed25519 public key on the pooled host with `omakase-server sleep-delegate enroll VM_UUID PUBLIC_KEY_HEX`. Protect the hypervisor-side signing key and keep its per-ticket submission claims for the lifetime of the key. The guest receives only the public key. Enrollment accepts the same binding on retry and rejects a change of VM or key.

1. The hook runs `omakase-server sleep-delegate hypervisor-begin`. Only after this succeeds, send the returned ticket to the enrolled provider using the deployment's authenticated management channel. Authorize that channel for this VM.
2. On the hypervisor host run `omakase-qmp-sleep pause /private/provider-state /private/qmp.sock TICKET`. The witness verifies the live UUID and running state, persists an exclusive single-use claim, submits QMP `stop`, observes `STOP` and verifies the paused state.
3. When ready to resume, send the line `resume TICKET` on the witness's standard input. On the same QMP connection it submits `cont`, observes `RESUME` and checks the running state and UUID before durably storing and printing `COMPLETED TICKET SIGNATURE`. This adapter tracks a vCPU pause/resume. The QMP endpoint and power operation must be under the witness's control. [QMP commands and events](https://www.qemu.org/docs/master/interop/qemu-qmp-ref.html)
4. Return the receipt to the pooled host and run `omakase-server sleep-delegate hypervisor-confirm TICKET SIGNATURE`. The signed bytes bind the protocol, VM and exact outstanding ticket. Another open slot continues to block dispatch.

If receipt delivery is interrupted, `omakase-qmp-sleep receipt /private/provider-state TICKET` retrieves the stored signature, including after a guest reboot. A provider that stopped before recording terminal evidence retains its single-use claim. A running VM, lost QMP connection, timeout and old signature cannot produce a replacement receipt. If the control channel breaks while paused, the administrator may need to resume the VM at its console. This alone leaves the pool gated. Reconcile the original authority's evidence before replacing an installation or its trust root.

The guest verifies an Ed25519 signature over three ASCII lines, each terminated by LF. The first line is `PathWard hypervisor sleep completed v1`, the second is the enrolled lowercase VM UUID and the third is the 64-character lowercase hexadecimal ticket. The signature argument uses 128 lowercase hexadecimal characters. Supporting another hypervisor requires an adapter that binds submission and authoritative terminal evidence to one operation before signing these bytes.

## Recover the original QEMU operation after witness loss

Use this contract for a new enrollment when the guest root or the submitting witness can be restored from a snapshot. It requires two independently retained stores. The guest-side guard disk holds the pending ticket. The hypervisor authority holds the one-use submission claim, an independent QMP observation and the signing key. Exclude both stores from guest and witness restores. Keep the enforcing server binary, disk attachment and mount requirement in the VM's boot contract. When upgrading a v1 deployment, finish any pending v1 ticket using its original evidence before attaching the new disk.

1. Give the guest a dedicated virtio block device with serial `pathward-qmp-guard`. Mount the whole ext4 or XFS device at `/var/lib/pathward-qmp-guard` before starting the server or any hook. Configure the serving unit with `RequiresMountsFor=/var/lib/pathward-qmp-guard`. Both the mount and the device metadata under `/dev/disk/by-id/` must be visible to the serving user. Omakase checks the device number, filesystem, ownership and installation binding. It takes a shared lock on the guard through the first socket write.
2. On the hypervisor, run `omakase-qmp-sleep keygen AUTH VM_UUID` on the independently retained volume. Both the observer and the submitting process need the same private `AUTH` directory with durable exclusive file creation and directory sync. Give the submitting process its own private `MIRROR` directory on its restorable volume. Use distinct private command and observation QMP Unix sockets connected to the same emulator in one host PID namespace. Keep these control paths under one administrator and serialize all power operations for this VM. The v1 and v2 commands share the same permanent per-ticket submission claim in `AUTH`.
3. In the guest, run `omakase-server sleep-delegate init-local` on a new installation, then `omakase-server sleep-delegate enroll-recoverable VM_UUID AUTH_PUBLIC_KEY`. Existing enrollment must be idle and use the same VM/key binding. A previous pending v1 ticket still requires its original v1 evidence.
4. Before submitting power work, run `omakase-server sleep-delegate hypervisor-begin` and forward the returned ticket over the deployment's authenticated management channel. Both the independent guard and the guest ledger are durably pending when the command succeeds.
5. Start `omakase-qmp-sleep observe AUTH OBS_QMP TICKET` as an independent process. Wait for `ARMED TICKET`. Then start `omakase-qmp-sleep pause-once MIRROR AUTH CMD_QMP TICKET`. It spends the durable one-use claim before contacting the command socket. Both monitors verify the UUID and the same live vCPU 0 host thread. The submitter checks its own STOP and the paused state before it records the acknowledgement and prints `PAUSED TICKET`.
6. Send `resume TICKET` on the submitter's standard input when ready. If the submitter dies after acknowledging the stop, the administrator can resume that VM at its trusted console. The independent observer must have stayed connected through the original STOP and RESUME, retain the matching acknowledgement and verify that the same emulator is running. Only then does it sign and store a terminal receipt. Additional lifecycle changes, including reset or migration, invalidate this observation. [QMP lifecycle and vCPU properties](https://www.qemu.org/docs/master/interop/qemu-qmp-ref.html)
7. Recover the receipt with `omakase-qmp-sleep reconcile AUTH TICKET`. This read-only lookup verifies the stored signature with the public key and works with the signing key offline. It opens no QMP connection. Deliver its `COMPLETED TICKET SIGNATURE` to the guest and run `omakase-server sleep-delegate hypervisor-confirm TICKET SIGNATURE`. Recovery can redeliver this signature after a guest or submitter restore. Its signed protocol line is `PathWard independently observed QEMU resume v2`, followed by the UUID and ticket, each terminated by LF.

`sleep-delegate status` shows the local hypervisor ticket and independent guard separately. A guest restored to idle remains closed while its disk guard holds a ticket. If an older local ticket and a newer guard disagree, deliver the older ticket's genuine receipt to clear just the local copy, then reconcile the current guard. The server persists local clearance before clearing the guard. Retrying after interruption therefore retains the same evidence requirement. A pending systemd service also keeps its own gate closed.

QMP STOP and RESUME events carry no application ticket. This protocol therefore requires exclusive coordination of power changes during the episode, including automatic pauses from other managers, watchdogs or storage error policies. If both observers lose the episode before recording terminal evidence, the authority keeps its active claim and the pool stays closed. A new QMP connection or a VM that answers health checks cannot recreate the original event history. Live RAM rewind and restoring the protected volumes themselves also require additional mediation. [QMP STOP and RESUME](https://www.qemu.org/docs/master/interop/qemu-qmp-ref.html) · [Disk-rollback tests](qmp-reconciliation-validation.json) · [Proof roadmap](../proofs/roadmap.json)

## What is verified

The serving path locks the durable directory before reading the ledger and holds that shared lock until the first socket write returns. The owner serializes registration and completion under the exclusive directory lock. It writes, syncs and renames a new state file and syncs the directory before returning the ticket or submitting work. A failed or partial update stays gated on ambiguous submission. Each retirement checks the relevant slot and leaves the other one intact.

Lean checks the extracted write and retirement decisions, and the effect of reservation, completion and reboot in a history of both owners. Filesystem durability, accurate terminal observations, unique tickets, signature verification and the provider's single-use store are operating assumptions. Unregistered root actions, independent storage rollback and other hypervisor protocols require separate mediation. [Theorems](../proofs/LinuxProofs.lean)

The Rust manifests and lockfiles are unchanged. The guest uses the existing rustix file and lock operations and ring's OS randomness and Ed25519 verifier. The host witness uses ring for signing and the administrator crate's duplicate-rejecting serde_json parser for QMP replies, bounded to 64 KiB per message. The systemd adapter uses the host's existing systemctl and busctl. The dependency audit covers all five Cargo lockfiles. [Isolated Linux measurements and dependency audit](pool-delegation-validation.json)
