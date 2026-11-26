export function findDuplicateEnvKeys(contents: string): {
  key: string;
  lines: number[];
}[];
export function formatDuplicateReport(
  duplicates: { key: string; lines: number[] }[],
): string;
