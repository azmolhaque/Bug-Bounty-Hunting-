# inscope-pkgs.sh — the one definition of "a package this program covers".
#
# Sourced, not executed. It sets MVRP_PKG_RE and nothing else.
#
# It lives here because the pattern was written once in mvrp-pull.sh and then
# needed by mvrp-update-diff.sh, and a second copy is a second thing to forget:
# the last time this list was wrong (four in-scope developers missing) the
# sweep reported "65 packages pulled" and looked healthy while skipping the
# target. A filter that silently excludes is worse than no filter.
#
# Derived from config/scope-mobile-vrp.yaml -> in_scope_developers.
MVRP_PKG_RE='com\.fitbit|com\.nest|com\.obsidian\.v4|com\.waze|com\.waymo|com\.google\.android\.apps\.|com\.google\.android\.gm$|com\.google\.android\.gms$|com\.google\.android\.googlequicksearchbox$|com\.google\.ar|com\.google\.samples|com\.google\.ai\.|com\.google\.fpl\.|com\.google\.looker$|com\.google\.play\.billing\.samples|com\.google\.audio\.hearing|com\.android\.developers\.|com\.redhotlabs\.'
