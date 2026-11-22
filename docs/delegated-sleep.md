# Tracking delegated sleep work

A local sleep hook can return while a separate service is running or a hypervisor still owns a pause. A Linux pooled first write requires an awake boot fence, an empty systemd slot, an empty hypervisor slot and the usual fresh backend health. The two slots can overlap. A second registration for an occupied slot fails before submission. Health probes, fixed upstreams and continuation of an already dispatched request retain their existing behavior.

## Provision a pooled host

Before starting the upgraded pooled server, run `pathward-server sleep-delegate init-local` once as the host administrator. This also enables local systemd delegation. The command creates a root-owned ledger in `/var/lib/pathward-sleep-delegates` and binds its directory inode and random installation ID to `/etc/pathward-sleep-delegates.id`. Share both paths with every serving process, including private mount namespaces. Store the ledger on persistent local storage. Hypervisor enrollment supports ext4, XFS and Btrfs.

Upgrade every pooled server before enabling a delegating hook, then run `pool-preflight CONFIG --control-dir DIR` for each one. The F2 observation compares both inodes. An old server, missing ledger, inaccessible anchor or mismatched identity blocks readiness. Cold boot initializes only the ordinary boot fence. A missing persistent record keeps first writes closed. Provisioning preserves an existing registration and rejects a missing ledger with a retained anchor. Keep both paths and the hypervisor witness store out of independent snapshot rollbacks.

## A separate systemd service

Install the shipped `deploy/pathward-delegated-sleep@.service` under `/etc/systemd/system/`, install the reviewed site-specific helper as `/usr/local/libexec/pathward-delegated-sleep` and run `systemctl daemon-reload`. The helper receives the ticket as its only argument. Its power work belongs to the instance cgroup. Further delegation needs its own registration. The originating hook invokes:

```sh
pathward-server sleep-delegate service-start
```

The command registers a fresh 256-bit ticket on disk before issuing one nonblocking start for `pathward-delegated-sleep@TICKET.service`. A pre-submission check validates the loaded template. If submission has an uncertain outcome, use `sleep-delegate status` to retrieve the ticket. In the host mount and cgroup namespaces, run:

```sh
pathward-server sleep-delegate service-check TICKET
```

The matching instance must have completed successfully in its original boot and clock domain. The check requires an exited oneshot retained by systemd, a valid invocation ID and exit timestamp, zero main/control PIDs, an empty job and an empty recursive cgroup. It reads the unit again after checking the cgroup. Both the start and completion checks reject additional lifecycle commands, including stop and reload hooks. After successful confirmation, the administrator can release the exited instance with `systemctl stop pathward-delegated-sleep@TICKET.service`. Use a fresh ticket for each job. Failed units, lost terminal evidence and a reboot before confirmation leave the slot closed. [systemd oneshot and RemainAfterExit](https://www.freedesktop.org/software/systemd/man/255/systemd.service.html) · [cgroup v2 population](https://docs.kernel.org/admin-guide/cgroup-v2.html#core-interface-files)

## A QEMU hypervisor

Build the optional native witness with `cargo build --release --locked --manifest-path admin/Cargo.toml --bin pathward-qmp-sleep`. On the hypervisor host, create a private persistent directory for one VM and its new signing key. Configure QEMU with this explicit nonzero VM UUID and a private Unix QMP monitor. Use a private, trusted parent directory for the witness directory and monitor socket.

```sh
pathward-qmp-sleep keygen /private/provider-state VM_UUID
```

Install the printed Ed25519 public key on the pooled host with `pathward-server sleep-delegate enroll VM_UUID PUBLIC_KEY_HEX`. Protect the hypervisor-side signing key and keep its per-ticket submission claims for the lifetime of the key. The guest receives only the public key. Enrollment accepts the same binding on retry and rejects a change of VM or key.

1. The hook runs `pathward-server sleep-delegate hypervisor-begin`. Only after this succeeds, send the returned ticket to the enrolled provider using the deployment's authenticated management channel. Authorize that channel for this VM.
2. On the hypervisor host run `pathward-qmp-sleep pause /private/provider-state /private/qmp.sock TICKET`. The witness verifies the live UUID and running state, persists an exclusive single-use claim, submits QMP `stop`, observes `STOP` and verifies the paused state.
3. When ready to resume, send the line `resume TICKET` on the witness's standard input. On the same QMP connection it submits `cont`, observes `RESUME` and checks the running state and UUID before durably storing and printing `COMPLETED TICKET SIGNATURE`. This adapter tracks a vCPU pause/resume. The QMP endpoint and power operation must be under the witness's control. [QMP commands and events](https://www.qemu.org/docs/master/interop/qemu-qmp-ref.html)
4. Return the receipt to the pooled host and run `pathward-server sleep-delegate hypervisor-confirm TICKET SIGNATURE`. The signed bytes bind the protocol, VM and exact outstanding ticket. Another open slot continues to block dispatch.

If receipt delivery is interrupted, `pathward-qmp-sleep receipt /private/provider-state TICKET` retrieves the stored signature, including after a guest reboot. A provider that stopped before recording terminal evidence retains its single-use claim. A running VM, lost QMP connection, timeout and old signature cannot produce a replacement receipt. If the control channel breaks while paused, the administrator may need to resume the VM at its console. This alone leaves the pool gated. Reconcile the original authority's evidence before replacing an installation or its trust root.

The guest verifies an Ed25519 signature over three ASCII lines, each terminated by LF. The first line is `PathWard hypervisor sleep completed v1`, the second is the enrolled lowercase VM UUID and the third is the 64-character lowercase hexadecimal ticket. The signature argument uses 128 lowercase hexadecimal characters. Supporting another hypervisor requires an adapter that binds submission and authoritative terminal evidence to one operation before signing these bytes.

## What is verified

The serving path locks the durable directory before reading the ledger and holds that shared lock until the first socket write returns. The owner serializes registration and completion under the exclusive directory lock. It writes, syncs and renames a new state file and syncs the directory before returning the ticket or submitting work. A failed or partial update stays gated on ambiguous submission. Each retirement checks the relevant slot and leaves the other one intact.

Lean checks the extracted write and retirement decisions, and the effect of reservation, completion and reboot in a history of both owners. Filesystem durability, accurate terminal observations, unique tickets, signature verification and the provider's single-use store are operating assumptions. Unregistered root actions, independent storage rollback and other hypervisor protocols require separate mediation. [Theorems](../proofs/LinuxProofs.lean)

The Rust manifests and lockfiles are unchanged. The guest uses the existing rustix file and lock operations and ring's OS randomness and Ed25519 verifier. The host witness uses ring for signing and the administrator crate's duplicate-rejecting serde_json parser for QMP replies, bounded to 64 KiB per message. The systemd adapter uses the host's existing systemctl and busctl. The dependency audit covers all five Cargo lockfiles. [Isolated Linux measurements and dependency audit](pool-delegation-validation.json)
