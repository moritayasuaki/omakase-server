import UpstreamProofs

open Aeneas Aeneas.Std RustM pathward
namespace PlatformProofs

/- The adapter supplies ordered samples from one generation clock. -/

theorem missing_tick_refuses_health (h : upstream.PoolHealth) :
    (do let t ← upstream.pool_tick none; upstream.fresh_health h t) = ok false := by
  simp [upstream.pool_tick, UpstreamProofs.fresh_at_eq, UpstreamProofs.FreshAt]

theorem tick_value (n : U128) :
    (do let t ← upstream.pool_tick (some n); ok t.val) =
      ok (min n.val 18446744073709551615) := by
  by_cases h : n.val < 18446744073709551615
  · simp [upstream.pool_tick, lift, U64.rMax, h, UScalar.cast_val_eq,
      UScalarTy.numBits, Nat.min_eq_left (Nat.le_of_lt h)]
    omega
  · simp [upstream.pool_tick, lift, U64.rMax, h, Nat.min_eq_right (Nat.le_of_not_gt h)]

theorem ordered_ticks_do_not_reverse (a b : U128) (ha : a.val ≤ b.val) :
    ∃ x y : Nat, (do let t ← upstream.pool_tick (some a); ok t.val) = ok x ∧
      (do let t ← upstream.pool_tick (some b); ok t.val) = ok y ∧ x ≤ y := by
  exact ⟨_, _, tick_value a, tick_value b, min_le_min_right _ ha⟩

theorem exhausted_tick_refuses_health (h : upstream.PoolHealth) (n : U128)
    (exhausted : 18446744073709551615 ≤ n.val) :
    (do let t ← upstream.pool_tick (some n); upstream.fresh_health h t) = ok false := by
  simp [upstream.pool_tick, lift, U64.rMax, Nat.not_lt.mpr exhausted,
    UpstreamProofs.fresh_at_eq, UpstreamProofs.FreshAt]

theorem expired_sample_stays_expired (h : upstream.PoolHealth) (earlier later : U64)
    (expired : h.at.val + 5000000000 ≤ earlier.val) (ordered : earlier.val ≤ later.val) :
    upstream.fresh_health h later = ok false := by
  simp [UpstreamProofs.fresh_at_eq, UpstreamProofs.FreshAt]
  omega

/- These functions are extracted from the slices used by the socket adapter. -/

theorem suffix_at_count (buf : Slice U8) (n : Usize) :
    upstream.write_suffix buf n =
      ok (if n.val ≤ buf.val.length then some (buf.drop n) else none) := by
  by_cases h : n.val ≤ buf.val.length <;>
    simp [upstream.write_suffix, Slice.index_SliceIndexRangeFromUsizeSliceInst,
      core.slice.index.SliceIndexRangeFromUsizeSlice.index, Slice.length, h]

theorem wait_keeps_every_byte (buf : Slice U8) :
    upstream.remaining_after_write buf none = ok (some buf) := by rfl

theorem zero_terminates (buf : Slice U8) :
    upstream.remaining_after_write buf (some 0#usize) = ok none := by rfl

theorem overreport_terminates (buf : Slice U8) (n : Usize) (over : buf.val.length < n.val) :
    upstream.remaining_after_write buf (some n) = ok none := by
  simp [upstream.remaining_after_write, suffix_at_count, Nat.not_le.mpr over]
  split <;> rfl

theorem accepted_prefix_and_suffix (buf rest : Slice U8) (n : Usize)
    (step : upstream.write_suffix buf n = ok (some rest)) :
    buf.val.take n.val ++ rest.val = buf.val := by
  rw [suffix_at_count] at step
  split at step <;> simp_all [Slice.drop]
  subst rest
  exact List.take_append_drop ..

theorem positive_count_uses_suffix (buf : Slice U8) (n : Usize) (pos : 0 < n.val) :
    upstream.remaining_after_write buf (some n) = upstream.write_suffix buf n := by
  simp only [upstream.remaining_after_write]
  split <;> simp_all

theorem positive_write_strictly_shortens (buf rest : Slice U8) (n : Usize) (pos : 0 < n.val)
    (step : upstream.remaining_after_write buf (some n) = ok (some rest)) :
    rest.val.length < buf.val.length := by
  rw [positive_count_uses_suffix buf n pos, suffix_at_count] at step
  split at step <;> simp_all [Slice.drop]
  subst rest
  simp
  omega

/-- A finite observation of one socket. Each piece records the prefix accepted
    by the corresponding write. The error case models WouldBlock or Interrupted. -/
inductive Transfer : Slice U8 → List (Option Usize) → List U8 → Slice U8 → Prop where
  | stop (buf) : Transfer buf [] [] buf
  | wait {buf next events accepted rest} :
      upstream.remaining_after_write buf none = ok (some next) →
      Transfer next events accepted rest → Transfer buf (none :: events) accepted rest
  | partialWrite {buf next events accepted rest n} :
      0 < n.val → upstream.remaining_after_write buf (some n) = ok (some next) →
      Transfer next events accepted rest →
      Transfer buf (some n :: events) (buf.val.take n.val ++ accepted) rest

theorem finite_trace_conserves_bytes {buf events accepted rest}
    (run : Transfer buf events accepted rest) : accepted ++ rest.val = buf.val := by
  induction run with
  | stop => rfl
  | wait step _ ih =>
    rw [wait_keeps_every_byte] at step
    cases step
    exact ih
  | partialWrite pos step _ ih =>
    rw [positive_count_uses_suffix _ _ pos] at step
    rw [List.append_assoc, ih]
    exact accepted_prefix_and_suffix _ _ _ step

theorem completed_after_first_write_is_original {buf afterFirst rest : Slice U8}
    {n events accepted} (first : upstream.write_suffix buf n = ok (some afterFirst))
    (run : Transfer afterFirst events accepted rest) (finished : rest.val = []) :
    buf.val.take n.val ++ accepted = buf.val := by
  have exactBytes := finite_trace_conserves_bytes run
  simp [finished] at exactBytes
  rw [exactBytes]
  exact accepted_prefix_and_suffix _ _ _ first

/-- A positive first return consumes the grant even when it is short. Any
    completed continuation accounts for exactly the original request bytes. -/
theorem partial_dispatch_cannot_replay {W V} (writer : upstream.FirstWriter W)
    (alternate : upstream.FirstWriter V) (m m' : Slice U32) (i i' : Usize)
    (g g' : upstream.FirstWriteGate) (w w' : W) (v : V) (n : Usize)
    (permit : UpstreamProofs.MayWrite m i g false) (pos : 0 < n.val)
    (io : writer.write_once w = ok (.Written n, w'))
    {buf suffix rest : Slice U8} {events accepted}
    (offset : upstream.write_suffix buf n = ok (some suffix))
    (trace : Transfer suffix events accepted rest) (finished : rest.val = []) :
    (do let (_, spent, _) ← upstream.guarded_first_write writer m i g false w
        upstream.guarded_first_write alternate m' i' g' spent v) = ok (none, true, v) ∧
    buf.val.take n.val ++ accepted = buf.val := by
  rw [UpstreamProofs.positive_write_spends_grant writer m i g false w permit n pos w' io]
  exact ⟨UpstreamProofs.spent_never_calls_another_writer alternate m' i' g' v,
    completed_after_first_write_is_original offset trace finished⟩

/- A successful lock acquisition, guarded mutation, or release is a linearized
   event. A blocked acquisition has no observable effect on protected state. -/
inductive Guards where
  | free | generation (owner : Nat) | both (owner : Nat)
  deriving DecidableEq

structure LockedState where
  guards : Guards
  retired : Bool
  health : upstream.PoolHealth

inductive Event where
  | takeGeneration | takeHealth | releaseHealth | releaseGeneration | retire
  | publish (sample : upstream.PoolHealth)

def lockStep (s : LockedState) (actor : Nat) (event : Event) : LockedState :=
  match s.guards, event with
  | .free, .takeGeneration => {s with guards := .generation actor}
  | .generation owner, .takeHealth =>
      if owner = actor then {s with guards := .both owner} else s
  | .both owner, .releaseHealth =>
      if owner = actor then {s with guards := .generation owner} else s
  | .generation owner, .releaseGeneration =>
      if owner = actor then {s with guards := .free} else s
  | .free, .retire => {s with retired := true}
  | .free, .publish h | .generation _, .publish h => {s with health := h}
  | _, _ => s

def lockRun (s : LockedState) (events : List (Nat × Event)) : LockedState :=
  events.foldl (fun state e => lockStep state e.1 e.2) s

theorem health_lock_requires_generation_first (s : LockedState) (actor : Nat)
    (free : s.guards = .free) :
    lockStep s actor .takeHealth = s ∧
    (lockStep (lockStep s actor .takeGeneration) actor .takeHealth).guards = .both actor := by
  simp [lockStep, free]

theorem owner_releases_health_before_generation (s : LockedState) (owner : Nat)
    (held : s.guards = .both owner) :
    lockStep s owner .releaseGeneration = s ∧
    (lockStep (lockStep s owner .releaseHealth) owner .releaseGeneration).guards = .free := by
  simp [lockStep, held]

theorem competing_events_preserve_both_guards (s : LockedState) (owner actor : Nat)
    (held : s.guards = .both owner) (other : actor ≠ owner) (e : Event) :
    lockStep s actor e = s := by
  cases e <;> simp [lockStep, held, Ne.symm other]

theorem foreign_interleavings_keep_snapshot (s : LockedState) (owner : Nat)
    (held : s.guards = .both owner) (events : List (Nat × Event))
    (foreign : ∀ e ∈ events, e.1 ≠ owner) : lockRun s events = s := by
  induction events with
  | nil => rfl
  | cons e es ih =>
    have other := foreign e (by simp)
    have tail : ∀ a ∈ es, a.1 ≠ owner := by intro a h; exact foreign a (by simp [h])
    simpa [lockRun, competing_events_preserve_both_guards s owner e.1 held other e.2] using ih tail

theorem retirement_survives_events (s : LockedState) (events : List (Nat × Event))
    (retired : s.retired = true) : (lockRun s events).retired = true := by
  induction events generalizing s with
  | nil => exact retired
  | cons e es ih =>
    apply ih (lockStep s e.1 e.2)
    cases h : s.guards <;> cases e.2 <;> simp [lockStep, h, retired] <;> split <;> simp_all

def lockedAttempt {W} (effect : upstream.FirstWriter W) (s : LockedState) (actor : Nat)
    (m : Slice U32) (i : Usize) (g : upstream.FirstWriteGate) (sent : Bool) (w : W) :=
  if s.guards = .both actor then
    upstream.guarded_first_write effect m i {g with health := s.health, retired := s.retired} sent w
  else ok (none, sent, w)

theorem effect_needs_owned_snapshot {W} (effect : upstream.FirstWriter W) (s : LockedState)
    (actor : Nat) (m : Slice U32) (i : Usize) (g : upstream.FirstWriteGate) (sent : Bool) (w : W)
    {event spent next} (out : lockedAttempt effect s actor m i g sent w = ok (some event, spent, next)) :
    s.guards = .both actor ∧ s.retired = false ∧ UpstreamProofs.FreshAt s.health g.now ∧
    200 ≤ s.health.status.val ∧ s.health.status.val < 300 := by
  unfold lockedAttempt at out
  split at out
  · rename_i owned
    obtain ⟨_, fresh, status, _, live, _⟩ :=
      UpstreamProofs.effect_targets_registered_healthy_peer effect m i _ sent w _ _ _ out
    exact ⟨owned, live, fresh, status⟩
  · cases out

end PlatformProofs
