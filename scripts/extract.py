#!/usr/bin/env python3
"""Re-extract the actual Rust entry point; fail on stale or unsupported output."""
import argparse
import difflib
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / ".tools/cache/hax/tools"
CHARON = TOOLS / "charon/nightly-2026.09.02/charon"
AENEAS = TOOLS / "aeneas/build-183e4f0/aeneas"
MODEL = ROOT / "proofs/Generated/Omakase.lean"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="compare without modifying the committed model")
    args = parser.parse_args()
    if not CHARON.is_file() or not AENEAS.is_file():
        raise SystemExit("Verification tools are missing; run make setup first.")
    version = subprocess.check_output([str(AENEAS), "-version"], text=True).strip()
    if version != "aeneas build-183e4f0":
        raise SystemExit(f"Unexpected Aeneas version: {version}")
    with tempfile.TemporaryDirectory(prefix="omakase-extract-") as temporary:
        output = Path(temporary)
        llbc = output / "omakase.llbc"
        subprocess.run([str(CHARON), "cargo", "--preset=aeneas", "--sysroot", "default",
                        "--start-from", "omakase::is_public",
                        "--start-from", "omakase::rules::compile",
                        "--start-from", "omakase::rules::lookup",
                        "--start-from", "omakase::serving::authorize",
                        "--start-from", "omakase::serving::file_allowed",
                        "--start-from", "omakase::tls::identity_allowed",
                        "--start-from", "omakase::tls::secret_allowed",
                        "--start-from", "omakase::tls::activate",
                        "--start-from", "omakase::tls::renewal_due",
                        "--start-from", "omakase::runtime::commit_generation",
                        "--start-from", "omakase::runtime::ready",
                        "--start-from", "omakase::response::header_allowed",
                        "--start-from", "omakase::response::redirect_allowed",
                        "--start-from", "omakase::response::route_matches",
                        "--start-from", "omakase::response::authority_port",
                        "--start-from", "omakase::response::authority_port_allowed",
                        "--start-from", "omakase::response::forwarded_port",
                        "--start-from", "omakase::release::generated_rule",
                        "--start-from", "omakase::release::commit_allowed",
                        "--start-from", "omakase::release::admission_allowed",
                        "--start-from", "omakase::release::admission_rejection",
                        "--start-from", "omakase::release::dispatch_allowed",
                        "--start-from", "omakase::release::capacity_global",
                        "--start-from", "omakase::release::capacity_peer",
                        "--start-from", "omakase::release::capacity_queue",
                        "--start-from", "omakase::release::capacity_rate",
                        "--start-from", "omakase::release::capacity_burst",
                        "--start-from", "omakase::release::capacity_rejection",
                        "--start-from", "omakase::release::capacity_reload_allowed",
                        "--start-from", "omakase::release::migration_allowed",
                        "--start-from", "omakase::proxy::site_mode_allowed",
                        "--start-from", "omakase::proxy::endpoint_allowed",
                        "--start-from", "omakase::proxy::method_allowed",
                        "--start-from", "omakase::proxy::status_allowed",
                        "--start-from", "omakase::proxy::request_framing",
                        "--start-from", "omakase::proxy::response_framing",
                        "--start-from", "omakase::proxy::upstream_body_mode",
                        "--start-from", "omakase::delivery::response_storage",
                        "--start-from", "omakase::proxy::target_allowed",
                        "--start-from", "omakase::proxy::request_header",
                        "--start-from", "omakase::proxy::response_header",
                        "--start-from", "omakase::routing::select",
                        "--start-from", "omakase::routing::stem",
                        "--start-from", "omakase::routing::subtree",
                        "--start-from", "omakase::routing::body_limit",
                        "--start-from", "omakase::routing::body_fits",
                        "--start-from", "omakase::routing::chunk_fits",
                        "--start-from", "omakase::routing::time_limits",
                        "--start-from", "omakase::routing::connection_limit",
                        "--start-from", "omakase::routing::service_admit",
                        "--start-from", "omakase::routing::request_framing",
                        "--start-from", "omakase::routing::response_framing",
                        "--start-from", "omakase::streaming::upgrade_request",
                        "--start-from", "omakase::streaming::upgrade_response",
                        "--start-from", "omakase::streaming::sse_response",
                        "--start-from", "omakase::streaming::byte_limit",
                        "--start-from", "omakase::streaming::bytes_fit",
                        "--start-from", "omakase::streaming::time_limits",
                        "--start-from", "omakase::streaming::running",
                        "--start-from", "omakase::streaming::admission",
                        "--start-from", "omakase::streaming::peer_admission",
                        "--start-from", "omakase::streaming::service_limit",
                        "--start-from", "omakase::streaming::service_admission",
                        "--start-from", "omakase::streaming::origin_allowed",
                        "--start-from", "omakase::streaming::deflate_allowed",
                        "--start-from", "omakase::content::span_allowed",
                        "--start-from", "omakase::content::precondition_status",
                        "--start-from", "omakase::content::shared_cache_allowed",
                        "--start-from", "omakase::upstream::probe_allowed",
                        "--start-from", "omakase::upstream::probe_next",
                        "--start-from", "omakase::upstream::probe_owned",
                        "--start-from", "omakase::upstream::query_match",
                        "--start-from", "omakase::upstream::pool_select",
                        "--start-from", "omakase::upstream::begin_dispatch",
                        "--start-from", "omakase::upstream::publish_health",
                        "--start-from", "omakase::upstream::publish_probe",
                        "--start-from", "omakase::upstream::retire_pool",
                        "--start-from", "omakase::upstream::guarded_first_write",
                        "--start-from", "omakase::upstream::sleep_fence_awake",
                        "--start-from", "omakase::upstream::cold_pool_health",
                        "--start-from", "omakase::upstream::pool_preflight_ready",
                        "--start-from", "omakase::upstream::pool_witness_current",
                        "--start-from", "omakase::upstream::sleep_recovery_allowed",
                        "--start-from", "omakase::upstream::delegates_allow_write",
                        "--start-from", "omakase::upstream::delegate_can_retire",
                        "--start-from", "omakase::upstream::pool_tick",
                        "--start-from", "omakase::upstream::remaining_after_write",
                        "--start-from", "omakase::upstream::first_write_report",
                        "--start-from", "omakase::delivery::reserve_allowed",
                        "--start-from", "omakase::delivery::multiplex_te_allowed",
                        "--start-from", "omakase::delivery::multiplex_body_allowed",
                        "--start-from", "omakase::delivery::shrink_allowed",
                        "--start-from", "omakase::delivery::phase_live",
                        "--start-from", "omakase::delivery::input_timeout_status",
                        "--start-from", "omakase::delivery::http1_persistent",
                        "--start-from", "omakase::delivery::reuse_allowed",
                        "--start-from", "omakase::delivery::request_credit",
                        "--start-from", "omakase::delivery::task_slot",
                        "--start-from", "omakase::delivery::encode_allowed",
                        "--start-from", "omakase::delivery::multiplex_slot",
                        "--start-from", "omakase::delivery::head_slot",
                        "--start-from", "omakase::delivery::held_action",
                        "--start-from", "omakase::delivery::retirement_close",
                        "--start-from", "omakase::delivery::h2_close_ready",
                        "--start-from", "omakase::delivery::h2_drain_expired",
                        "--start-from", "omakase::delivery::h2_peer_drain_allowed",
                        "--start-from", "omakase::delivery::cancel_slot",
                        "--start-from", "omakase::delivery::early_allowed",
                        "--start-from", "omakase::delivery::wire_fits",
                        "--start-from", "omakase::connection::candidate_slot",
                        "--start-from", "omakase::connection::request_live",
                        "--start-from", "omakase::connection::launch_allowed",
                        "--start-from", "omakase::connection::success_allowed",
                        "--start-from", "omakase::cutover::stop_old_allowed",
                        "--start-from", "omakase::cutover::window_allowed",
                        "--start-from", "omakase::cutover::commit_allowed",
                        "--start-from", "omakase::cutover::disarm_allowed",
                        "--start-from", "omakase::cutover::watchdog_required",
                        "--start-from", "omakase::bootstrap::preparation_allowed",
                        "--start-from", "omakase::bootstrap::package_allowed",
                        "--start-from", "omakase::bootstrap::asset_allowed",
                        "--start-from", "omakase::bootstrap::restore_allowed",
                        "--start-from", "omakase::bootstrap::reviewed_asset_allowed",
                        "--start-from", "omakase::bootstrap::bridge_receipt_allowed",
                        "--start-from", "omakase::bootstrap::sealed_resource_allowed",
                        "--start-from", "omakase::bootstrap::license_text_allowed",
                        "--start-from", "omakase::publication::mapping_allowed",
                        "--start-from", "omakase::publication::receipt_allowed",
                        "--start-from", "omakase::publication::collection_allowed",
                        "--start-from", "omakase::recovery::select",
                        "--start-from", "omakase::recovery::upgrade_action",
                        "--start-from", "omakase::recovery::migration_allowed",
                        "--start-from", "omakase::recovery::collection_allowed",
                        "--start-from", "omakase::recovery::contract_install_allowed",
                        "--start-from", "omakase::recovery::contract_commit_allowed",
                        "--start-from", "omakase::recovery::contract_gate_allowed",
                        "--start-from", "omakase::recovery::contract_recovery_choice",
                        "--start-from", "omakase::recovery::contract_watchdog_allowed",
                        "--start-from", "omakase::recovery::start_allowed",
                        "--start-from", "omakase::recovery::stop_old_allowed",
                        "--start-from", "omakase::recovery::trial_allowed",
                        "--start-from", "omakase::recovery::fallback_allowed",
                        "--dest-file", str(llbc), "--", "--lib"],
                       cwd=ROOT, check=True)
        subprocess.run([str(AENEAS), "-backend", "lean", "-loops-to-rec", "-no-progress-bar",
                        "-abort-on-error", "-warnings-as-errors", "-dest", str(output), str(llbc)],
                       cwd=ROOT, check=True)
        generated = (output / "Omakase.lean").read_text()
        if re.search(r"\b(sorry|admit|axiom|opaque)\b", generated):
            raise SystemExit("Extraction contains an unverified placeholder or external declaration")
        if args.check:
            committed = MODEL.read_text()
            if committed != generated:
                print("".join(difflib.unified_diff(committed.splitlines(True), generated.splitlines(True),
                                                 fromfile="committed model", tofile="current Rust extraction")))
                raise SystemExit("Stale Lean extraction. Run make extract and update the proofs.")
        else:
            MODEL.parent.mkdir(parents=True, exist_ok=True)
            MODEL.write_text(generated)
    print("Rust extraction matches the committed model." if args.check else "Rust model extracted.")


if __name__ == "__main__":
    main()
