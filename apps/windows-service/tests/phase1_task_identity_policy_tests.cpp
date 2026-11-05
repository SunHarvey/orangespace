// Portable policy tests; not Windows or Task Scheduler observations.
#include "phase1_task_identity_policy.hpp"
#include <cstdio>
#include <cstdlib>
static void require(bool value, const char* name) {
  if (!value) { std::fprintf(stderr, "FAIL %s\n", name); std::exit(1); }
}
int main() {
  using namespace phase1_task_identity;
  Evidence e;
  require(classify(e) == Finding::authority_unknown, "default unknown denies");
  e.external_authority = e.held_protected_roots = e.fixed_images = e.observer_token = true;
  require(classify(e) == Finding::task_instance_unknown, "no task instance denies");
  e.exact_task_instance = true;
  require(classify(e) == Finding::engine_unknown, "missing COM engine denies");
  e.engine_process_held = true;
  require(classify(e) == Finding::engine_not_fixed_probe, "engine is not assumed action");
  e.engine_image_is_fixed_probe = true;
  require(classify(e) == Finding::probe_identity_unknown, "matching image insufficient");
  e.probe_token = e.process_creation_checked = e.engine_instance_rechecked = true;
  require(classify(e) == Finding::action_binding_unproved, "even equality is not invented API contract");
  require(!further_admission(e), "no further admission even all observations true");
  // Actual behavior negatives, not only source spelling assertions.
  for (unsigned i = 0; i != 10; ++i) {
    Evidence changed = e;
    bool* fields[] = {&changed.external_authority, &changed.held_protected_roots,
      &changed.fixed_images, &changed.observer_token, &changed.exact_task_instance,
      &changed.engine_process_held, &changed.engine_image_is_fixed_probe,
      &changed.probe_token, &changed.process_creation_checked, &changed.engine_instance_rechecked};
    *fields[i] = false;
    require(classify(changed) != Finding::action_binding_unproved, "each missing premise distinguished");
    require(!further_admission(changed), "negative never admits");
  }
  // Portable evaluation of the exact conservative ACL predicate used by the
  // native held-object validator; this is NOT native AccessCheck evidence.
  require(!conservative_ace(false, false, false, false, 0, 0), "unknown ACE denies even zero mask");
  require(!conservative_ace(false, false, false, true, 2, 2), "ordinary effective mutator denies");
  require(conservative_ace(false, true, false, true, 2, 2), "inherit-only not effective here");
  require(conservative_ace(false, false, true, true, 2, 2), "deny does not grant mutation");
  require(conservative_ace(true, false, false, true, 2, 2), "trusted administrator mutator");
  require(conservative_ace(false, false, false, true, 1, 2), "nonmutating read");
  for (unsigned i = 0; i < 32; ++i)
    require(!conservative_ace(false, false, false, true, 1UL << i, 1UL << i), "each effective mutation bit denied");
  std::puts("portable premise-policy and conservative ACE predicate: all checks passed; native acceptance NOT RUN; admission=false");
}
