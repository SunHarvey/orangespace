#pragma once
// Negative premise classifier only. These Booleans confer no OS authority.
// There is deliberately no native admission/success state in this first slice.
namespace phase1_task_identity {
struct Evidence {
  bool external_authority{};
  bool held_protected_roots{};
  bool fixed_images{};
  bool observer_token{};
  bool exact_task_instance{};
  bool engine_process_held{};
  bool engine_image_is_fixed_probe{};
  bool probe_token{};
  bool process_creation_checked{};
  bool engine_instance_rechecked{};
};
enum class Finding {
  authority_unknown, task_instance_unknown, engine_unknown,
  engine_not_fixed_probe, probe_identity_unknown, action_binding_unproved
};
constexpr Finding classify(const Evidence& e) noexcept {
  if (!e.external_authority || !e.held_protected_roots || !e.fixed_images || !e.observer_token)
    return Finding::authority_unknown;
  if (!e.exact_task_instance) return Finding::task_instance_unknown;
  if (!e.engine_process_held) return Finding::engine_unknown;
  if (!e.engine_image_is_fixed_probe) return Finding::engine_not_fixed_probe;
  if (!e.probe_token || !e.process_creation_checked || !e.engine_instance_rechecked)
    return Finding::probe_identity_unknown;
  return Finding::action_binding_unproved;
}
constexpr bool further_admission(const Evidence&) noexcept { return false; }
constexpr bool conservative_ace(bool trusted, bool inherit_only, bool denied, bool known,
                                unsigned long mask, unsigned long mutation) noexcept {
  return known && (inherit_only || denied || trusted || !(mask & mutation));
}
}
