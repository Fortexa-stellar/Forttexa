import { describe, expect, it } from 'vitest';
import { toCsv } from '@/utils/csv.utils';
import type { CsvRow } from '@/utils/csv.utils';
import maliciousData from './fixtures/malicious-csv-data.json';
import benignData from './fixtures/benign-csv-data.json';

describe('CSV Formula Injection Prevention (Issue #38)', () => {
  describe('malicious data fixtures', () => {
    it('neutralizes all formula injection attempts in malicious fixture', () => {
      const csv = toCsv(maliciousData as CsvRow[]);
      
      // Verify CSV was generated
      expect(csv).toBeTruthy();
      expect(csv.length).toBeGreaterThan(0);
      
      // Split into lines for analysis
      const lines = csv.trim().split('\n');
      expect(lines.length).toBe(maliciousData.length + 1); // header + data rows
      
      // Check that dangerous prefixes are neutralized in data rows (skip header)
      const dataRows = lines.slice(1);
      
      for (const row of dataRows) {
        // After proper sanitization, dangerous chars should be preceded by a quote
        // The pattern looks for any cell that starts with dangerous char WITHOUT the safety quote
        // We want to ensure that pattern does NOT exist
        
        // Extract all cells (accounting for quoted cells with embedded commas)
        const cells = row.match(/"(?:[^"]|"")*"/g) || [];
        
        for (const cell of cells) {
          // Remove outer quotes and unescape doubled quotes
          const content = cell.slice(1, -1).replace(/""/g, '"');
          
          // If content starts with dangerous char after whitespace, it must be preceded by '
          if (/^\s*[=+\-@]/.test(content)) {
            // The first character should be the safety quote
            expect(content[0]).toBe("'");
          }
        }
      }
    });

    it('preserves data integrity while neutralizing formulas', () => {
      const csv = toCsv(maliciousData as CsvRow[]);
      
      // Malicious values should be present but neutralized
      expect(csv).toContain('"\' cmd|'); // userId from first row
      expect(csv).toContain('"\'+malicious-action"'); // actionId
      expect(csv).toContain('"\'=SUM(A1:A100)'); // actionName
      expect(csv).toContain('"\'@malicious.domain"'); // domain
      expect(csv).toContain('"\' \t-1+1+cmd'); // explanation with tabs
    });

    it('neutralizes formulas with various whitespace patterns', () => {
      const csv = toCsv(maliciousData as CsvRow[]);
      
      // Space before dangerous char
      expect(csv).toContain('"\' =DANGEROUS_USER"');
      expect(csv).toContain('"\' +ATTACK_ID"');
      
      // Tab before dangerous char
      expect(csv).toContain('"\'\t@MALICIOUS()"');
      
      // Multiple spaces
      expect(csv).toContain('"\' -evil.com"');
      
      // Mixed whitespace (space + tab)
      expect(csv).toContain('"\' \t-1+1+cmd');
    });

    it('neutralizes all four dangerous prefixes: =, +, -, @', () => {
      const csv = toCsv(maliciousData as CsvRow[]);
      
      // Equals sign
      expect(csv).toContain('"\' cmd|'); // =cmd in userId
      expect(csv).toContain('"\'=SUM('); // =SUM in actionName
      expect(csv).toContain('"\'=1+1"'); // =1+1 in explanation
      
      // Plus sign
      expect(csv).toContain('"\'+malicious-action"'); // actionId
      expect(csv).toContain('"\' +ATTACK_ID"'); // actionId with space
      expect(csv).toContain('"\'+plus prefix'); // explanation
      
      // Minus sign
      expect(csv).toContain('"\'-negative-id"'); // actionId
      expect(csv).toContain('"\' -evil.com"'); // domain
      
      // At sign
      expect(csv).toContain('"\'@malicious.domain"'); // domain
      expect(csv).toContain('"\'\t@MALICIOUS()"'); // actionName
      expect(csv).toContain('"\'@SUM(1+1)"'); // domain
    });
  });

  describe('benign data fixtures', () => {
    it('preserves all benign values without alteration', () => {
      const csv = toCsv(benignData as CsvRow[]);
      
      // Verify CSV was generated
      expect(csv).toBeTruthy();
      expect(csv.length).toBeGreaterThan(0);
      
      // Should NOT contain any formula prefix quotes
      expect(csv).not.toContain('"\'"');
    });

    it('maintains data integrity for normal audit entries', () => {
      const csv = toCsv(benignData as CsvRow[]);
      
      // Check that normal values are present and unmodified
      expect(csv).toContain('"GCTEST123ABC"');
      expect(csv).toContain('"audit-001"');
      expect(csv).toContain('"ALLOW"');
      expect(csv).toContain('"action-safe-123"');
      expect(csv).toContain('"Normal Payment to Vendor"');
      expect(csv).toContain('"trusted-vendor.com"');
      expect(csv).toContain('"100.5"');
      expect(csv).toContain('"Routine payment within policy limits"');
    });

    it('handles all decision types correctly', () => {
      const csv = toCsv(benignData as CsvRow[]);
      
      expect(csv).toContain('"ALLOW"');
      expect(csv).toContain('"BLOCK"');
      expect(csv).toContain('"REQUIRE_APPROVAL"');
    });

    it('preserves special characters that are not formula prefixes', () => {
      const csv = toCsv(benignData as CsvRow[]);
      
      // These should be unmodified (dangerous chars not at start)
      expect(csv).toContain('"Invoice payment #12345"'); // # in middle
      expect(csv).toContain('"bigvendor.example"'); // . in middle
      expect(csv).toContain('"unknown-domain.xyz"'); // - and . in middle
      expect(csv).toContain('"saas-provider.com"'); // - in middle
    });
  });

  describe('all user-derived columns coverage', () => {
    it('covers userId column (derived from wallet address)', () => {
      const testData: CsvRow[] = [
        { userId: '=MALICIOUS', other: 'value' },
        { userId: 'SAFE_USER', other: 'value' },
      ];
      const csv = toCsv(testData);
      
      expect(csv).toContain('"\'=MALICIOUS"');
      expect(csv).toContain('"SAFE_USER"');
    });

    it('covers actionId column (user-controlled)', () => {
      const testData: CsvRow[] = [
        { actionId: '+evil-id', other: 'value' },
        { actionId: 'safe-id', other: 'value' },
      ];
      const csv = toCsv(testData);
      
      expect(csv).toContain('"\'+evil-id"');
      expect(csv).toContain('"safe-id"');
    });

    it('covers actionName column (user-controlled)', () => {
      const testData: CsvRow[] = [
        { actionName: '-dangerous action', other: 'value' },
        { actionName: 'Safe Action', other: 'value' },
      ];
      const csv = toCsv(testData);
      
      expect(csv).toContain('"\'-dangerous action"');
      expect(csv).toContain('"Safe Action"');
    });

    it('covers domain column (user-controlled)', () => {
      const testData: CsvRow[] = [
        { domain: '@evil.com', other: 'value' },
        { domain: 'safe.com', other: 'value' },
      ];
      const csv = toCsv(testData);
      
      expect(csv).toContain('"\'@evil.com"');
      expect(csv).toContain('"safe.com"');
    });

    it('covers explanation column (user-controlled)', () => {
      const testData: CsvRow[] = [
        { explanation: '=FORMULA()', other: 'value' },
        { explanation: 'Safe explanation', other: 'value' },
      ];
      const csv = toCsv(testData);
      
      expect(csv).toContain('"\'=FORMULA()"');
      expect(csv).toContain('"Safe explanation"');
    });

    it('covers amountXLM column (numeric but can be negative)', () => {
      const testData: CsvRow[] = [
        { amountXLM: -100, other: 'value' },
        { amountXLM: 100, other: 'value' },
      ];
      const csv = toCsv(testData);
      
      // Negative numbers start with - so should be sanitized
      expect(csv).toContain('"\'-100"');
      expect(csv).toContain('"100"');
    });
  });

  describe('edge cases', () => {
    it('handles empty strings', () => {
      const testData: CsvRow[] = [{ field: '', other: 'value' }];
      const csv = toCsv(testData);
      
      expect(csv).toContain('""');
    });

    it('handles only whitespace', () => {
      const testData: CsvRow[] = [{ field: '   ', other: 'value' }];
      const csv = toCsv(testData);
      
      expect(csv).toContain('"   "');
    });

    it('handles dangerous char as only character', () => {
      const testData: CsvRow[] = [
        { field: '=', other: 'value' },
        { field: '+', other: 'value' },
        { field: '-', other: 'value' },
        { field: '@', other: 'value' },
      ];
      const csv = toCsv(testData);
      
      expect(csv).toContain('"\'="');
      expect(csv).toContain('"\'+\"');
      expect(csv).toContain('"\'-\"');
      expect(csv).toContain('"\'@"');
    });

    it('handles dangerous chars with only whitespace after', () => {
      const testData: CsvRow[] = [
        { field: '=   ', other: 'value' },
        { field: ' +  ', other: 'value' },
      ];
      const csv = toCsv(testData);
      
      expect(csv).toContain('"\'=   "');
      expect(csv).toContain('"\' +  "');
    });

    it('does not alter strings with dangerous chars in middle', () => {
      const testData: CsvRow[] = [
        { field: 'A=B', other: 'value' },
        { field: '1+1', other: 'value' },
        { field: 'foo-bar', other: 'value' },
        { field: 'user@example.com', other: 'value' },
      ];
      const csv = toCsv(testData);
      
      expect(csv).toContain('"A=B"');
      expect(csv).toContain('"1+1"');
      expect(csv).toContain('"foo-bar"');
      expect(csv).toContain('"user@example.com"');
      
      // Should NOT have formula prefix
      expect(csv).not.toContain('"\'A=B"');
      expect(csv).not.toContain('"\'1+1"');
      expect(csv).not.toContain('"\'foo-bar"');
      expect(csv).not.toContain('"\'user@');
    });
  });

  describe('RFC 4180 compliance', () => {
    it('maintains proper CSV quoting with formula sanitization', () => {
      const testData: CsvRow[] = [
        { field: '=EVIL(), with "quotes" and, commas', other: 'value' },
      ];
      const csv = toCsv(testData);
      
      // Should have formula prefix AND proper quote escaping
      expect(csv).toContain('"\' EVIL(), with ""quotes"" and, commas"');
    });

    it('handles newlines in sanitized fields', () => {
      const testData: CsvRow[] = [
        { field: '=EVIL()\nwith\nnewlines', other: 'value' },
      ];
      const csv = toCsv(testData);
      
      // Should preserve newlines within quoted field
      expect(csv).toContain('"\' EVIL()\nwith\nnewlines"');
    });
  });
});
