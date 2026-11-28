import { cookies } from "next/headers";

import { ActivityTimeline } from "@/components/activity-timeline";
import { AUTH_COOKIE_KEY, verifySessionToken } from "@/lib/auth/session";
import { isSessionRevoked } from "@/lib/auth/session-revocation";
import { listAuditEntries } from "@/lib/storage/audit-store";

export default async function ActivityPage() {
  // Same source and shape as the dashboard and the settings activity tab:
  // the signed-in user's AuditEntry[] from the audit store.
  const cookieStore = await cookies();
  const sessionToken = cookieStore.get(AUTH_COOKIE_KEY)?.value;
  const session = sessionToken ? verifySessionToken(sessionToken) : null;
  // A valid signature is not enough: a logged-out token still verifies, so ask
  // the server's revocation store (the same one requireActiveAuth and
  // /api/auth/session use) before reading anything for this user.
  const active = session && !(await isSessionRevoked(session.sid)) ? session : null;
  const entries = active ? await listAuditEntries(active.userId) : [];

  return (
    <div className="container mx-auto p-4">
      <h1 className="text-2xl font-bold mb-6">Activity</h1>
      <ActivityTimeline entries={entries} />
    </div>
  );
}
