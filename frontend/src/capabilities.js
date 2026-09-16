const ROLE_CAPABILITIES = Object.freeze({
  admin: new Set([
    "manage_dashboard",
    "generate_reports",
    "export_audit_data",
    "edit_changelog",
    "manage_users",
    "review_access",
    "manage_access_reviews",
    "view_iam"
  ]),
  auditor: new Set([
    "generate_reports",
    "export_audit_data",
    "review_access",
    "view_iam"
  ]),
  viewer: new Set()
});

export function hasCapability(user, capability) {
  return Boolean(ROLE_CAPABILITIES[user?.role]?.has(capability));
}

export function capabilitiesForRole(role) {
  return [...(ROLE_CAPABILITIES[role] || [])];
}
