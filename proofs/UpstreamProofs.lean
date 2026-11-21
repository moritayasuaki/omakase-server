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
end UpstreamProofs
