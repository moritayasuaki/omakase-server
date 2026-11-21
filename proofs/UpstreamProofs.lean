import RoutingProofs
open Aeneas Aeneas.Std RustM pathward
namespace UpstreamProofs

theorem probe_eq (g c r : Bool) (b n : U64) :
    upstream.probe_allowed g b c r n = ok (decide (g = true ∧ b.val = 0 ∧ c = false ∧ r = true ∧ 0 < n.val ∧ n.val ≤ 32)) := by
  simp [upstream.probe_allowed]
  split_ifs <;> simp_all

theorem probe_read_only (g c r : Bool) (b n : U64)
    (h : upstream.probe_allowed g b c r n = ok true) :
    g = true ∧ b.val = 0 ∧ c = false := by
  simp [probe_eq] at h
  exact ⟨h.1,h.2.1,h.2.2.1⟩

theorem probe_bounded (g c r : Bool) (b n : U64)
    (h : upstream.probe_allowed g b c r n = ok true) : 0 < n.val ∧ n.val ≤ 32 := by
  simp [probe_eq] at h
  exact h.2.2.2.2

theorem next_eq (s : U16) (n : U64) :
    upstream.probe_next s n = ok (decide (s = 404#u16 ∧ 0 < n.val ∧ n.val < 32)) := by
  simp [upstream.probe_next]
  split_ifs <;> simp_all

theorem only_absence_falls_through (s : U16) (n : U64)
    (h : upstream.probe_next s n = ok true) : s = 404#u16 := by
  simp [next_eq] at h
  exact h.1

theorem no_retry_after_last (s : U16) : upstream.probe_next s 0#u64 = ok false := by simp [next_eq]

theorem owned_eq (s : U16) : upstream.probe_owned s = ok (decide
    ((200 ≤ s.val ∧ s.val < 300) ∨ s = 401#u16 ∨ s = 403#u16 ∨ s = 410#u16)) := by
  simp [upstream.probe_owned]
  split_ifs <;> simp_all

theorem authorization_is_final (n : U64) :
    upstream.probe_owned 401#u16 = ok true ∧ upstream.probe_next 401#u16 n = ok false ∧
    upstream.probe_owned 403#u16 = ok true ∧ upstream.probe_next 403#u16 n = ok false := by
  simp [owned_eq,next_eq]

theorem gone_is_final (n : U64) : upstream.probe_owned 410#u16 = ok true ∧ upstream.probe_next 410#u16 n = ok false := by simp [owned_eq,next_eq]

theorem server_error_is_not_owner (s : U16) (h : 500 ≤ s.val) : upstream.probe_owned s = ok false := by
  rw [owned_eq]
  have h401 : s ≠ 401#u16 := by intro he; subst s; simp at h
  have h403 : s ≠ 403#u16 := by intro he; subst s; simp at h
  have h410 : s ≠ 410#u16 := by intro he; subst s; simp at h
  simp [h401,h403,h410]; omega

theorem query_eq (e a : Bool) : upstream.query_match e a = ok (e || a) := by
  cases e <;> cases a <;> rfl

theorem encoded_query_applies (e : Bool) : upstream.query_match e true = ok true := by simp [query_eq]

theorem pool_closed (m : Slice U32) (i : Usize) (r d s : Bool)
    (h : r = false ∨ d = true ∨ s = true) :
    upstream.pool_select m i r d s = ok 0#u32 := by
  rcases h with h | h | h
  · subst r; rfl
  · subst d; cases r <;> rfl
  · subst s; cases r <;> cases d <;> rfl

theorem pool_selected_member (m : Slice U32) (i : Usize) (r d s : Bool) (out : U32)
    (select : upstream.pool_select m i r d s = ok out) (nonzero : out ≠ 0#u32) :
    out ∈ m.val ∧ r = true ∧ d = false ∧ s = false := by
  by_cases closed : r = false ∨ d = true ∨ s = true
  · rw [pool_closed m i r d s closed] at select
    simp_all
  · have hr : r = true := by cases r <;> simp_all
    have hd : d = false := by cases d <;> simp_all
    have hs : s = false := by cases s <;> simp_all
    subst r; subst d; subst s
    by_cases cap : Slice.len m ≤ 32#usize
    · by_cases bound : i < Slice.len m
      · have hi : i.val < m.val.length := by simpa using bound
        have eq : m.val[i.val] = out := by
          simpa [upstream.pool_select, cap, bound, PathwardProofs.index_eq m i hi] using select
        exact ⟨eq ▸ List.getElem_mem hi, rfl, rfl, rfl⟩
      · simp_all [upstream.pool_select]
    · simp_all [upstream.pool_select]

theorem dispatch_once (before : Bool) :
    upstream.begin_dispatch before = ok (!before, true) := by cases before <;> rfl

theorem dispatched_write_cannot_repeat (before after : Bool)
    (h : upstream.begin_dispatch before = ok (true, after)) :
    upstream.begin_dispatch after = ok (false, true) := by
  cases before <;> cases after <;> first | rfl | cases h

theorem dispatched_write_has_no_alternate (m : Slice U32) (i : Usize) (r d before after : Bool)
    (h : upstream.begin_dispatch before = ok (true, after)) :
    upstream.pool_select m i r d after = ok 0#u32 := by
  have ha : after = true := by cases before <;> cases after <;> first | rfl | cases h
  exact pool_closed m i r d after (Or.inr (Or.inr ha))

abbrev FreshAt (h : upstream.PoolHealth) (now : U64) : Prop :=
  h.revision ≠ 0#u64 ∧ h.revision ≠ core.num.U64.MAX ∧ now ≠ core.num.U64.MAX ∧ h.at.val ≤ now.val ∧
  now.val - h.at.val < 5000000000

theorem fresh_at_eq (h : upstream.PoolHealth) (now : U64) :
    upstream.fresh_health h now = ok (decide (FreshAt h now)) := by
  by_cases hz : h.revision = 0#u64
  · simp [upstream.fresh_health, FreshAt, hz]
  by_cases hm : h.revision = core.num.U64.MAX
  · simp [upstream.fresh_health, FreshAt, hm]
  by_cases hx : now = core.num.U64.MAX
  · simp [upstream.fresh_health, FreshAt, hx]
  by_cases ht : h.at.val ≤ now.val
  · obtain ⟨age, ha, hv, _⟩ := WP.spec_imp_exists (U64.sub_bv_spec (x := now) (y := h.at) ht)
    simp [upstream.fresh_health, FreshAt, hz, hm, hx, ht, ha, hv]
  · simp [upstream.fresh_health, FreshAt, hz, hm, hx, ht]

theorem health_status_eq (s : U16) :
    upstream.healthy_response s = ok (decide (200 ≤ s.val ∧ s.val < 300)) := by
  simp [upstream.healthy_response]; split_ifs <;> simp_all

theorem stale_probe_keeps_health (h : upstream.PoolHealth) (expected now : U64) (s : U16)
    (stale : expected ≠ h.revision) : upstream.publish_health h expected now s = ok h := by
  simp [upstream.publish_health, stale]

theorem health_update_advances (h : upstream.PoolHealth) (now : U64) (s : U16)
    (live : h.revision.val < 18446744073709551615) (ordered : h.at.val ≤ now.val) :
    ∃ h', upstream.publish_health h h.revision now s = ok h' ∧
    h'.revision.val = h.revision.val + 1 ∧ h'.at = now ∧ h'.status = s := by
  obtain ⟨v, hv, hvv, _⟩ := WP.spec_imp_exists (U64.add_bv_spec (x := h.revision) (y := 1#u64) (by scalar_tac))
  have hm : h.revision ≠ core.num.U64.MAX := by
    intro e; rw [e] at live; simp [core.num.U64.MAX, U64.rMax] at live
  have hn : ¬ now < h.at := by simpa using ordered
  exact ⟨⟨v, now, s⟩, by simp [upstream.publish_health, hm, hn, hv], by simpa using hvv, rfl, rfl⟩

theorem late_success_cannot_revive_failure (h : upstream.PoolHealth) (failed later : U64) (status : U16)
    (live : h.revision.val < 18446744073709551615) (ordered : h.at.val ≤ failed.val) :
    ∃ down, upstream.publish_health h h.revision failed 0#u16 = ok down ∧ down.status = 0#u16 ∧
      upstream.publish_health down h.revision later status = ok down := by
  obtain ⟨down, update, next, _, code⟩ := health_update_advances h failed 0#u16 live ordered
  refine ⟨down, update, code, stale_probe_keeps_health down h.revision later status ?_⟩
  intro e
  rw [e] at next
  omega

def memberAt (m : Slice U32) (i : Usize) : U32 :=
  if Slice.len m ≤ 32#usize then
    if h : i.val < m.val.length then m.val[i.val] else 0#u32
  else 0#u32

theorem pool_select_exact (m : Slice U32) (i : Usize) (ready drain sent : Bool) :
    upstream.pool_select m i ready drain sent = ok
      (if ready && !drain && !sent then memberAt m i else 0#u32) := by
  cases ready <;> cases drain <;> cases sent <;> try rfl
  by_cases cap : Slice.len m ≤ 32#usize
  · by_cases bound : i < Slice.len m
    · have hi : i.val < m.val.length := by simpa using bound
      simp [upstream.pool_select, memberAt, cap, bound, hi, PathwardProofs.index_eq m i hi]
    · have hi : ¬ i.val < m.val.length := by simpa using bound
      simp [upstream.pool_select, memberAt, cap, bound, hi]
  · simp [upstream.pool_select, memberAt, cap]

abbrev MayWrite (m : Slice U32) (i : Usize) (g : upstream.FirstWriteGate) (sent : Bool) : Prop :=
  g.peer ≠ 0#u32 ∧ FreshAt g.health g.now ∧ (200 ≤ g.health.status.val ∧ g.health.status.val < 300) ∧
  g.draining = false ∧ g.retired = false ∧ sent = false ∧ memberAt m i = g.peer

theorem first_write_contract (m : Slice U32) (i : Usize) (g : upstream.FirstWriteGate) (sent : Bool) :
    upstream.first_write_allowed m i g sent = ok (decide (MayWrite m i g sent)) := by
  rcases g with ⟨peer, health, now, drain, retired⟩
  by_cases hp : peer = 0#u32 <;> by_cases hf : FreshAt health now <;>
    by_cases hs : 200 ≤ health.status.val ∧ health.status.val < 300 <;>
    cases drain <;> cases retired <;> cases sent <;>
    simp [upstream.first_write_allowed, fresh_at_eq, health_status_eq, pool_select_exact,
      MayWrite, hp, hf, hs] <;> grind

variable {W : Type} (effect : upstream.FirstWriter W) (m : Slice U32) (i : Usize)
  (g : upstream.FirstWriteGate) (sent : Bool) (w : W)

theorem refused_preserves_writer (closed : ¬ MayWrite m i g sent) :
    upstream.guarded_first_write effect m i g sent w = ok (none, sent, w) := by
  simp [upstream.guarded_first_write, first_write_contract, closed]

theorem effect_result_requires_permission (event : upstream.FirstIo) (s : Bool) (next : W)
    (out : upstream.guarded_first_write effect m i g sent w = ok (some event, s, next)) :
    MayWrite m i g sent := by
  by_contra closed
  rw [refused_preserves_writer effect m i g sent w closed] at out
  cases out

theorem effect_targets_registered_healthy_peer (event : upstream.FirstIo) (s : Bool) (next : W)
    (out : upstream.guarded_first_write effect m i g sent w = ok (some event, s, next)) :
    g.peer ∈ m.val ∧ FreshAt g.health g.now ∧ (200 ≤ g.health.status.val ∧ g.health.status.val < 300) ∧
    g.draining = false ∧ g.retired = false ∧ sent = false := by
  obtain ⟨nz, fresh, status, active, current, unsent, peer⟩ :=
    effect_result_requires_permission effect m i g sent w event s next out
  have select : upstream.pool_select m i true false false = ok g.peer := by
    simpa [pool_select_exact] using peer
  exact ⟨(pool_selected_member m i true false false g.peer select nz).1, fresh, status, active, current, unsent⟩

theorem retirement_prevents_first_write (old : Bool) :
    (do let retired ← upstream.retire_pool old
        upstream.guarded_first_write effect m i {g with retired} sent w) = ok (none, sent, w) := by
  simp [upstream.retire_pool, upstream.guarded_first_write, first_write_contract, MayWrite]

theorem unusable_health_preserves_writer
    (bad : ¬ FreshAt g.health g.now ∨ ¬ (200 ≤ g.health.status.val ∧ g.health.status.val < 300)) :
    upstream.guarded_first_write effect m i g sent w = ok (none, sent, w) := by
  apply refused_preserves_writer
  unfold MayWrite; grind

theorem allowed_executes_one_write (permit : MayWrite m i g sent) :
    upstream.guarded_first_write effect m i g sent w = (do
      let (event, w') ← effect.write_once w
      match event with
      | .Wait => ok (some .Wait, sent, w')
      | .Written n => match n.val with
        | 0 => ok (some .Failed, true, w')
        | _ => ok (some (.Written n), true, w')
      | .Failed => ok (some .Failed, true, w')) := by
  simp [upstream.guarded_first_write, first_write_contract, permit, dispatch_once]
  intro event next eq
  cases event <;> rfl

theorem positive_write_spends_grant (permit : MayWrite m i g sent) (n : Usize) (npos : 0 < n.val) (w' : W)
    (io : effect.write_once w = ok (.Written n, w')) :
    upstream.guarded_first_write effect m i g sent w = ok (some (.Written n), true, w') := by
  rw [allowed_executes_one_write effect m i g sent w permit, io]
  cases h : n.val <;> simp_all

theorem empty_or_failed_write_is_terminal (permit : MayWrite m i g sent) (w' : W)
    (io : effect.write_once w = ok (.Written 0#usize, w') ∨ effect.write_once w = ok (.Failed, w')) :
    upstream.guarded_first_write effect m i g sent w = ok (some .Failed, true, w') := by
  rw [allowed_executes_one_write effect m i g sent w permit]
  rcases io with h | h <;> rw [h] <;> rfl

theorem wait_then_retirement_cannot_write (permit : MayWrite m i g sent) (w' : W)
    (io : effect.write_once w = ok (.Wait, w')) :
    (do let (_, s, next) ← upstream.guarded_first_write effect m i g sent w
        let retired ← upstream.retire_pool g.retired
        upstream.guarded_first_write effect m i {g with retired} s next) = ok (none, sent, w') := by
  rw [allowed_executes_one_write effect m i g sent w permit, io]
  exact retirement_prevents_first_write effect m i g sent w' g.retired

theorem spent_never_calls_another_writer :
    upstream.guarded_first_write effect m i g true w = ok (none, true, w) := by
  apply refused_preserves_writer
  simp [MayWrite]

theorem write_then_retire_cannot_dispatch_again (permit : MayWrite m i g sent)
    (n : Usize) (npos : 0 < n.val) (w' : W) (io : effect.write_once w = ok (.Written n, w')) :
    (do let (_, s, next) ← upstream.guarded_first_write effect m i g sent w
        let retired ← upstream.retire_pool g.retired
        upstream.guarded_first_write effect m i {g with retired} s next) = ok (none, true, w') := by
  rw [positive_write_spends_grant effect m i g sent w permit n npos w' io]
  exact retirement_prevents_first_write effect m i g true w' g.retired

end UpstreamProofs
