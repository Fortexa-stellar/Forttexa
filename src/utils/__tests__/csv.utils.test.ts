import { describe, expect, it } from 'vitest';
import { escapeCsvCell, sanitizeCsvCell, toCsv } from '@/utils/csv.utils';

describe('sanitizeCsvCell', () => {
  it('prepends a single quote for dangerous prefixes', () => {
    const inputs = ['=SUM(A1)', '+1', '-foo', '@bar'];
    const expected = ["'=SUM(A1)", "'+1", "'-foo", "'@bar"]; // note the leading single quote
    inputs.forEach((input, idx) => {
      expect(sanitizeCsvCell(input)).toBe(expected[idx]);
    });
  });

  it('neutralizes formulas with leading whitespace (spaces)', () => {
    expect(sanitizeCsvCell(' =SUM(A1)')).toBe("' =SUM(A1)");
    expect(sanitizeCsvCell('  +1')).toBe("'  +1");
    expect(sanitizeCsvCell('   -foo')).toBe("'   -foo");
    expect(sanitizeCsvCell('    @bar')).toBe("'    @bar");
  });

  it('neutralizes formulas with leading whitespace (tabs)', () => {
    expect(sanitizeCsvCell('\t=SUM(A1)')).toBe("'\t=SUM(A1)");
    expect(sanitizeCsvCell('\t\t+1')).toBe("'\t\t+1");
  });

  it('neutralizes formulas with mixed leading whitespace', () => {
    expect(sanitizeCsvCell(' \t =SUM(A1)')).toBe("' \t =SUM(A1)");
    expect(sanitizeCsvCell('\t  +1')).toBe("'\t  +1");
  });

  it('leaves safe strings unchanged', () => {
    expect(sanitizeCsvCell('Hello World')).toBe('Hello World');
    expect(sanitizeCsvCell('12345')).toBe('12345');
    expect(sanitizeCsvCell('=')).toBe("'="); // even a single '=' should be quoted
  });

  it('leaves strings with dangerous chars in middle unchanged', () => {
    expect(sanitizeCsvCell('A=B')).toBe('A=B');
    expect(sanitizeCsvCell('1+1')).toBe('1+1');
    expect(sanitizeCsvCell('foo-bar')).toBe('foo-bar');
    expect(sanitizeCsvCell('user@example.com')).toBe('user@example.com');
  });

  it('converts null/undefined to empty string', () => {
    expect(sanitizeCsvCell(null)).toBe('');
    expect(sanitizeCsvCell(undefined)).toBe('');
  });

  it('handles numbers correctly', () => {
    expect(sanitizeCsvCell(123)).toBe('123');
    expect(sanitizeCsvCell(-456)).toBe("'-456"); // negative number starts with -
  });

  it('handles malicious payloads from OWASP CSV Injection examples', () => {
    // Real-world attack vectors
    expect(sanitizeCsvCell('=cmd|"/c calc"!A1')).toBe("'=cmd|'/c calc'!A1");
    expect(sanitizeCsvCell('=1+1+cmd|"/c calc"!A1')).toBe("'=1+1+cmd|'/c calc'!A1");
    expect(sanitizeCsvCell('@SUM(1+1)*cmd|"/c calc"!A1')).toBe("'@SUM(1+1)*cmd|'/c calc'!A1");
    expect(sanitizeCsvCell('+1+1+cmd|"/c calc"!A1')).toBe("'+1+1+cmd|'/c calc'!A1");
    expect(sanitizeCsvCell('-1+1+cmd|"/c calc"!A1')).toBe("'-1+1+cmd|'/c calc'!A1");
  });
});

describe('escapeCsvCell', () => {
  it('quotes every cell and doubles embedded double quotes', () => {
    expect(escapeCsvCell('plain')).toBe('"plain"');
    expect(escapeCsvCell('a,b')).toBe('"a,b"');
    expect(escapeCsvCell('say "hi"')).toBe('"say ""hi"""');
  });

  it('keeps commas and quotes inside a single quoted cell', () => {
    // Round-trips through the same quoting rules a spreadsheet parser applies.
    const escaped = escapeCsvCell('Approved by ops, note: "temporary exception"');
    expect(escaped).toBe('"Approved by ops, note: ""temporary exception"""');
  });

  it('serializes redaction placeholders as JSON instead of [object Object]', () => {
    expect(escapeCsvCell({ $redacted: 'token' })).toBe('"{""$redacted"":""token""}"');
  });

  it('still hardens formula prefixes', () => {
    expect(escapeCsvCell('=1+1')).toBe('"\'=1+1"');
  });
});

describe('toCsv', () => {
  it('returns an empty body when there are no rows', () => {
    expect(toCsv([])).toBe('');
  });

  it('emits a header and one line per row', () => {
    const csv = toCsv([
      { id: 'entry-1', explanation: 'Within policy limits' },
      { id: 'entry-2', explanation: 'Approved by ops, note: "temporary exception"' },
    ]);

    expect(csv).toBe(
      [
        'id,explanation',
        '"entry-1","Within policy limits"',
        '"entry-2","Approved by ops, note: ""temporary exception"""',
        '',
      ].join('\n')
    );
  });

  it('keeps a comma/quote-bearing value inside one column', () => {
    const csv = toCsv([{ id: 'entry-1', actionName: 'pay, "urgent"' }]);
    const [header, row] = csv.trimEnd().split('\n');

    // The value is emitted as a single quoted cell with doubled quotes, so a
    // CSV-aware parser recovers exactly two columns despite the embedded comma.
    expect(header).toBe('id,actionName');
    expect(row).toBe('"entry-1","pay, ""urgent"""');
  });

  describe('formula injection protection across all user-derived columns', () => {
    it('sanitizes actionName (user-controlled)', () => {
      const csv = toCsv([
        { userId: 'user1', actionName: '=MALICIOUS()' },
        { userId: 'user2', actionName: ' +ATTACK' },
      ]);
      
      expect(csv).toContain('"\'=MALICIOUS()"');
      expect(csv).toContain('"\' +ATTACK"');
    });

    it('sanitizes domain (user-controlled)', () => {
      const csv = toCsv([
        { userId: 'user1', domain: '@malicious.com' },
        { userId: 'user2', domain: '\t-evil.org' },
      ]);
      
      expect(csv).toContain('"\'@malicious.com"');
      expect(csv).toContain('"\'\t-evil.org"');
    });

    it('sanitizes explanation (user-controlled)', () => {
      const csv = toCsv([
        { userId: 'user1', explanation: '=SUM(A1:A100)' },
        { userId: 'user2', explanation: '  @DANGEROUS' },
      ]);
      
      expect(csv).toContain('"\'=SUM(A1:A100)"');
      expect(csv).toContain('"\' @DANGEROUS"');
    });

    it('sanitizes actionId (user-controlled)', () => {
      const csv = toCsv([
        { userId: 'user1', actionId: '+id-with-plus' },
        { userId: 'user2', actionId: '-id-with-minus' },
      ]);
      
      expect(csv).toContain('"\'+id-with-plus"');
      expect(csv).toContain('"\'-id-with-minus"');
    });

    it('sanitizes userId (derived from wallet address)', () => {
      const csv = toCsv([
        { userId: '=MALICIOUS_USER', actionName: 'test' },
        { userId: ' @attacker', actionName: 'test' },
      ]);
      
      expect(csv).toContain('"\'=MALICIOUS_USER"');
      expect(csv).toContain('"\' @attacker"');
    });

    it('handles benign values in all columns without alteration', () => {
      const csv = toCsv([
        {
          userId: 'GCTEST123',
          id: 'audit-001',
          timestamp: '2026-11-24T12:00:00Z',
          decision: 'ALLOW',
          actionId: 'action-123',
          actionName: 'Normal Payment',
          domain: 'example.com',
          amountXLM: 100.5,
          explanation: 'Routine transaction',
        },
      ]);

      // All benign values should be present without quote prefix
      expect(csv).toContain('"GCTEST123"');
      expect(csv).toContain('"audit-001"');
      expect(csv).toContain('"ALLOW"');
      expect(csv).toContain('"action-123"');
      expect(csv).toContain('"Normal Payment"');
      expect(csv).toContain('"example.com"');
      expect(csv).toContain('"100.5"');
      expect(csv).toContain('"Routine transaction"');
      
      // Should NOT contain formula prefix
      expect(csv).not.toContain('"\'"');
    });

    it('neutralizes complex attack vectors with multiple formulas', () => {
      const csv = toCsv([
        {
          userId: '=cmd|"/c calc"!A1',
          actionName: '+1+1+cmd|"/c notepad"!A1',
          domain: '@SUM(A1:A999)',
          explanation: ' \t-1+1+HYPERLINK("http://evil.com")',
        },
      ]);

      // All dangerous values should have formula prefix neutralized
      expect(csv).toContain('"\' cmd|');
      expect(csv).toContain('"\'+1+1+cmd');
      expect(csv).toContain('"\'@SUM(A1:A999)"');
      expect(csv).toContain('"\' \t-1+1+HYPERLINK');
    });
  });
});
