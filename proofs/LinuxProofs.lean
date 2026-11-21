import PlatformProofs
import Generated.GuardPaths

open Aeneas Aeneas.Std RustM pathward
namespace LinuxProofs

/- The emitted paths include normal returns and unwinds. A guard in an
   unsuccessful PoisonError is disposed of by the pinned standard library.
   This automaton tracks the two guards acquired by the caller. -/
inductive Held where | neither | generation | both

def scopeValid : Held → Bool → List PoolMir.Event → Bool
  | .neither, _, [.returned] | .neither, _, [.unwind] => true
  | .neither, false, .takeGeneration :: tail => scopeValid .generation false tail
  | .generation, false, .takeHealth :: tail => scopeValid .both false tail
  | .both, false, .invoke :: tail => scopeValid .both true tail
  | .both, called, .dropHealth :: tail => scopeValid .generation called tail
  | .generation, called, .dropGeneration :: tail => scopeValid .neither called tail
  | _, _, _ => false

theorem all_emitted_guard_paths_are_scoped (p : List PoolMir.Event) (member : p ∈ PoolMir.paths) :
    scopeValid .neither false p = true := by
  have checked : PoolMir.paths.all (scopeValid .neither false) = true := by decide
  exact List.all_eq_true.mp checked p member

theorem callback_returns_or_unwinds_through_both_drops (p : List PoolMir.Event)
    (emitted : p ∈ PoolMir.paths) (called : .invoke ∈ p) :
    ∃ last, (last = PoolMir.Event.returned ∨ last = .unwind) ∧
      p = [.takeGeneration, .takeHealth, .invoke, .dropHealth, .dropGeneration, last] := by
  simp only [PoolMir.paths, List.mem_cons, List.not_mem_nil, or_false] at emitted
  rcases emitted with h | h | h | h | h | h | h <;> subst p <;> simp_all

open PlatformProofs in
/-- The release/acquire edge publishes the whole health record. The actor
    reading it may differ from the one that published the revision. -/
theorem acquire_after_publication_observes_complete_record (s : LockedState) (publisher reader : Nat)
    (free : s.guards = .free) (revision now : U64) (status : U16) (h : upstream.PoolHealth)
    (published : upstream.publish_health s.health revision now status = ok h) :
    (do let record ← upstream.publish_health s.health revision now status
        let acquired := lockRun s [(publisher, .publish record), (reader, .takeGeneration), (reader, .takeHealth)]
        ok (acquired.guards, acquired.health, acquired.retired)) = ok (.both reader, h, s.retired) := by
  simp [published, lockRun, lockStep, free]

/- Active nanoseconds are relative to one pool origin. Linux supplies the
   suspend-excluding monotonic clock and the suspend-inclusive boot clock. -/
structure Clocks where
  active : U128
  suspended : Nat

def boot (c : Clocks) := c.active.val + c.suspended
def sleepFor (c : Clocks) (ns : Nat) : Clocks := {c with suspended := c.suspended + ns}
def healthAt (h : upstream.PoolHealth) (c : Clocks) : RustM Bool := do
  let t ← upstream.pool_tick (some c.active)
  upstream.fresh_health h t

theorem sleep_advances_only_boot_age (c : Clocks) (ns : Nat) (h : upstream.PoolHealth) :
    boot (sleepFor c ns) = boot c + ns ∧ healthAt h (sleepFor c ns) = healthAt h c := by
  exact ⟨by simp [boot, sleepFor, Nat.add_assoc], rfl⟩

theorem long_suspend_can_preserve_fresh_probe (c : Clocks) (ns : Nat) (h : upstream.PoolHealth)
    (fresh : healthAt h c = ok true) (long : 5000000000 ≤ ns) :
    5000000000 ≤ boot (sleepFor c ns) - boot c ∧ healthAt h (sleepFor c ns) = ok true := by
  obtain ⟨delta, same⟩ := sleep_advances_only_boot_age c ns h
  rw [delta, same]
  exact ⟨by omega, fresh⟩

theorem instant_delta_within_kernel_brackets (lo₀ read₀ hi₀ lo₁ read₁ hi₁ origin : Nat)
    (a : lo₀ ≤ read₀) (b : read₀ ≤ hi₀) (c : lo₁ ≤ read₁) (d : read₁ ≤ hi₁)
    (originBound : origin ≤ lo₀) (ordered : hi₀ ≤ lo₁) :
    lo₁ - hi₀ ≤ (read₁-origin) - (read₀-origin) ∧
      (read₁-origin) - (read₀-origin) ≤ hi₁ - lo₀ := by omega

theorem first_report_retains_errno {E} (e : E) :
    upstream.first_write_report (.Err e) = ok (.Failed, some e) ∧
    upstream.first_write_report (E := E) (.Ok none) = ok (.Wait, none) := by exact ⟨rfl, rfl⟩

theorem first_report_retains_partial_count (E : Type) (n : Usize) :
    upstream.first_write_report (E := E) (.Ok (some n)) = ok (.Written n, none) := by rfl

def reportedWriter {E : Type} (report : core.result.Result (Option Usize) E) :
    upstream.FirstWriter (Option E) := ⟨fun _ => upstream.first_write_report report⟩

theorem fatal_first_report_spends_grant_with_original_cause {E : Type} (e : E)
    (m : Slice U32) (i : Usize) (g : upstream.FirstWriteGate) (permit : UpstreamProofs.MayWrite m i g false) :
    upstream.guarded_first_write (reportedWriter (.Err e)) m i g false none = ok (some .Failed, true, some e) := by
  apply UpstreamProofs.empty_or_failed_write_is_terminal _ m i g false none permit
  exact Or.inr rfl

theorem retryable_first_report_requires_live_generation {E : Type}
    (m : Slice U32) (i : Usize) (g : upstream.FirstWriteGate) (permit : UpstreamProofs.MayWrite m i g false) :
    (do let (_, spent, next) ← upstream.guarded_first_write (reportedWriter (E := E) (.Ok none)) m i g false none
        let retired ← upstream.retire_pool g.retired
        upstream.guarded_first_write (reportedWriter (E := E) (.Ok none)) m i {g with retired} spent next) =
      ok (none, false, none) := by
  apply UpstreamProofs.wait_then_retirement_cannot_write _ m i g false none permit
  rfl

/-- Socket identity is an observation in the model. The adapter owns a single
    TcpStream, and the Linux fixture independently measures its SO_COOKIE. -/
inductive SocketState (E : Type) where
  | live (rest : Slice U8)
  | stopped (reason : Option E) (rest : Slice U8)
  | wrongSocket

abbrev Report (E : Type) := U64 × core.result.Result (Option Usize) E

def socketStep {E} (id : U64) (state : SocketState E) (event : Report E) : RustM (SocketState E) :=
  match state with
  | .live buf =>
    if event.1 ≠ id then ok .wrongSocket else match event.2 with
    | .Err e => ok (.stopped (some e) buf)
    | .Ok count => do
      let rest ← upstream.remaining_after_write buf count
      match rest with
      | some bytes => ok (.live bytes)
      | none => ok (.stopped none buf)
  | other => ok other

def socketRun {E} (id : U64) (state : SocketState E) : List (Report E) → RustM (SocketState E)
  | [] => ok state
  | e :: es => do
    let next ← socketStep id state e
    socketRun id next es

theorem stopped_preserves_errno_and_suffix {E} (id : U64) (why : Option E) (buf : Slice U8)
    (tail : List (Report E)) : socketRun id (.stopped why buf) tail = ok (.stopped why buf) := by
  induction tail with
  | nil => rfl
  | cons _ _ ih => simpa [socketRun, socketStep] using ih

theorem foreign_socket_is_rejected {E} (id other : U64) (different : other ≠ id) (buf : Slice U8)
    (result : core.result.Result (Option Usize) E) :
    socketStep id (.live buf) (other, result) = ok .wrongSocket := by simp [socketStep, different]

theorem retryable_report_keeps_socket_cursor {E} (id : U64) (buf : Slice U8) (tail : List (Report E)) :
    socketRun id (.live buf) ((id, .Ok none) :: tail) = socketRun id (.live buf) tail := by
  simp [socketRun, socketStep, PlatformProofs.wait_keeps_every_byte]

theorem fatal_after_partial_preserves_exact_unaccepted_suffix {E} (id : U64) (buf rest : Slice U8)
    (n : Usize) (positive : 0 < n.val)
    (accepted : upstream.remaining_after_write buf (some n) = ok (some rest))
    (e : E) (tail : List (Report E)) :
    socketRun id (.live buf) ((id, .Ok (some n)) :: (id, .Err e) :: tail) = ok (.stopped (some e) rest) ∧
    buf.val.take n.val ++ rest.val = buf.val := by
  constructor
  · simp [socketRun, socketStep, accepted, stopped_preserves_errno_and_suffix]
  · rw [PlatformProofs.positive_count_uses_suffix buf n positive] at accepted
    exact PlatformProofs.accepted_prefix_and_suffix _ _ _ accepted

end LinuxProofs
