'use client';

import { Clock4, ScrollText } from "lucide-react";

import { DecisionBadge } from "@/components/decision-badge";
import { Card, CardContent } from "@/components/ui/card";
import { formatAuditTimestamp } from "@/lib/utils/format";
import type { AuditEntry } from "@/lib/types/domain";

export function ActivityTimeline({
  entries = [],
  compact = false,
}: {
  entries?: AuditEntry[];
  compact?: boolean;
}) {
  if (!entries || entries.length === 0) {
    return (
      <Card>
        <CardContent className="py-10 text-center text-sm text-[hsl(var(--muted-foreground))]">
          No audit entries yet. Run an evaluation in the Console to populate this timeline.
        </CardContent>
      </Card>
    );
  }

  const visible = compact ? entries.slice(0, 5) : entries;

  return (
    <div className="relative space-y-3">
      {!compact ? (
        <div className="absolute bottom-0 left-[7px] top-0 hidden w-px bg-[hsl(var(--border))] md:block" />
      ) : null}
      {visible.map((entry) => {
        const timeInfo = formatAuditTimestamp(entry.timestamp);

        return (
          <div
            key={entry.id}
            className={`relative surface rounded-xl p-4 transition hover:border-[hsl(var(--accent)/0.15)] ${compact ? "" : "md:ml-5"}`}
          >
            {!compact ? (
              <div className="absolute -left-[3px] top-6 hidden h-2 w-2 rounded-full border border-[hsl(var(--accent)/0.5)] bg-[hsl(var(--accent)/0.3)] md:block" />
            ) : null}
            <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-start">
              <div className="min-w-0 flex-1">
                <p className="font-medium break-words">{entry.action.name}</p>
                <p className="mt-0.5 text-xs text-[hsl(var(--muted-foreground))]">
                  {timeInfo.isValid && timeInfo.dateTime ? (
                    <time dateTime={timeInfo.dateTime}>{timeInfo.formatted}</time>
                  ) : (
                    <time>{timeInfo.formatted}</time>
                  )}
                  {" "}· {entry.action.amountXLM} XLM
                </p>
              </div>
              <div className="flex shrink-0 sm:block">
                <DecisionBadge decision={entry.decision} />
              </div>
            </div>
            {!compact ? (
              <div className="mt-3 space-y-2 text-sm text-[hsl(var(--muted-foreground))]">
                <p className="rounded-lg bg-[hsl(var(--muted)/0.35)] px-3 py-2 break-words">{entry.explanation}</p>
                <p className="inline-flex items-center gap-1 text-xs break-all">
                  <ScrollText aria-hidden="true" className="h-3 w-3 shrink-0" /> {entry.id}
                </p>
              </div>
            ) : (
              <p className="mt-2 truncate text-xs text-[hsl(var(--muted-foreground))]">{entry.explanation}</p>
            )}
            {!compact ? (
              <div className="mt-2 grid gap-2 sm:grid-cols-3">
                <div className="rounded-lg bg-[hsl(var(--muted)/0.35)] px-3 py-2 text-xs">
                  <p className="mb-0.5 uppercase tracking-wider text-[hsl(var(--accent))]">Tool</p>
                  <p className="truncate" title={entry.action.name}>
                    {entry.action.name}
                  </p>
                </div>
                <div className="rounded-lg bg-[hsl(var(--muted)/0.35)] px-3 py-2 text-xs">
                  <p className="mb-0.5 uppercase tracking-wider text-[hsl(var(--accent))]">Amount</p>
                  {entry.action.amountXLM} XLM
                </div>
                <div className="rounded-lg bg-[hsl(var(--muted)/0.35)] px-3 py-2 text-xs">
                  <p className="mb-0.5 inline-flex items-center gap-1 uppercase tracking-wider text-[hsl(var(--accent))]">
                    <Clock4 aria-hidden="true" className="h-3 w-3" /> Time
                  </p>
                  {timeInfo.isValid && timeInfo.dateTime ? (
                    <time dateTime={timeInfo.dateTime}>{timeInfo.timeOnly}</time>
                  ) : (
                    <time>{timeInfo.timeOnly}</time>
                  )}
                </div>
              </div>
            ) : null}
          </div>
        );
      })}
    </div>
  );
}
