const DAY_MS = 86_400_000;

export function expiryPresentation(record = {}, retentionDays, now = Date.now()) {
  if (record.state !== "quarantined") {
    return { eligible: false, eligibleAt: null, phrase: null, message: "" };
  }
  if (retentionDays === null || retentionDays === undefined) {
    return {
      eligible: false,
      eligibleAt: null,
      phrase: null,
      message: "Permanent expiry is disabled.",
    };
  }
  if (!Number.isInteger(retentionDays) || retentionDays < 1 || retentionDays > 3650) {
    return {
      eligible: false,
      eligibleAt: null,
      phrase: null,
      message: "The saved retention policy is invalid.",
    };
  }
  if (!record.quarantined_at || !Array.isArray(record.peer_paths) || !record.peer_paths.length) {
    return {
      eligible: false,
      eligibleAt: null,
      phrase: null,
      message: "Legacy evidence: restore is available, permanent expiry is not.",
    };
  }
  const eligibleAt = Number(record.quarantined_at) + retentionDays * DAY_MS;
  const eligible = Number.isFinite(eligibleAt) && now >= eligibleAt;
  return {
    eligible,
    eligibleAt,
    phrase: `expire ${record.id}`,
    message: eligible
      ? "Eligible for manually confirmed permanent expiry."
      : `Protected until ${new Date(eligibleAt).toLocaleString()}.`,
  };
}
