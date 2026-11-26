import { cookies } from "next/headers";

import { ActivityTimeline } from "@/components/activity-timeline";
import { AUTH_COOKIE_KEY, verifySessionToken } from "@/lib/auth/session";
import { listAuditEntries } from "@/lib/storage/audit-store";

export default async function ActivityPage() {
  const cookieStore = await cookies();
  const sessionToken = cookieStore.get(AUTH_COOKIE_KEY)?.value;
  const session = sessionToken ? verifySessionToken(sessionToken) : null;
  const entries = session?.userId ? await listAuditEntries(session.userId) : [];

  return (
    <div className="container mx-auto p-4">
      <h1 className="mb-6 text-2xl font-bold">Activity</h1>
      <ActivityTimeline entries={entries} />
    </div>
  );
}
