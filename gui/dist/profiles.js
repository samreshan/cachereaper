export function exclusionSections(config = {}, knownRuleIds = new Set()) {
  const section = (title, paths = [], rules = [], profileId = null) => ({
    title, profileId, paths: [...paths],
    rules: rules.map((id) => ({ id, available: knownRuleIds.has(id) })),
  });
  return [
    section("Global exclusions", config.global_excluded_paths, config.global_excluded_rules),
    ...(config.profiles || []).map((profile) =>
      section(`${profile.name} — ${profile.root}`, profile.excluded_paths, profile.excluded_rules, profile.id)),
  ];
}
