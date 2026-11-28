/** One env key that is assigned more than once, with the 1-based line numbers. */
export interface DuplicateEnvKey {
  key: string;
  lines: number[];
}

export function findDuplicateEnvKeys(content: string): DuplicateEnvKey[];

export function formatDuplicateReport(duplicates: DuplicateEnvKey[]): string;

export function checkEnvFile(filePath: string): { ok: boolean; report: string };
