import { expect } from 'chai';
import { enhanceFindingsWithContext } from '../src/services/contextAwareFilter.js';

describe('enhanceFindingsWithContext', () => {
  it('returns findings unchanged when no file path', async () => {
    const findings = [{ severity: 'high', vulnType: 'SQL_INJECTION' }];
    const result = await enhanceFindingsWithContext(findings, '/nonexistent');
    expect(result).to.have.length(1);
    expect(result[0].severity).to.equal('high');
  });

  it('returns findings unchanged when line number is 0', async () => {
    const findings = [{ severity: 'high', location: 'foo.js', line: 0, vulnType: 'SQL_INJECTION' }];
    const result = await enhanceFindingsWithContext(findings, '/nonexistent');
    expect(result).to.have.length(1);
  });

  it('reduces confidence for test files', async () => {
    const findings = [{ severity: 'high', location: 'src/test/foo.java', line: 10, vulnType: 'SQL_INJECTION' }];
    const result = await enhanceFindingsWithContext(findings, '/nonexistent');
    expect(result[0].confidence).to.be.lessThan(0.5);
    expect(result[0].guardContext.isTestFile).to.be.true;
  });

  it('reduces confidence for mock files', async () => {
    const findings = [{ severity: 'high', location: 'src/mock/auth.js', line: 5, vulnType: 'XSS' }];
    const result = await enhanceFindingsWithContext(findings, '/nonexistent');
    expect(result[0].confidence).to.be.lessThan(0.5);
  });

  it('reduces confidence for spec files', async () => {
    const findings = [{ severity: 'high', location: 'user.spec.ts', line: 5, vulnType: 'XSS' }];
    const result = await enhanceFindingsWithContext(findings, '/nonexistent');
    expect(result[0].confidence).to.be.lessThan(0.5);
  });

  it('detects guard pattern in real file', async () => {
    const fs = await import('node:fs/promises');
    const os = await import('node:os');
    const path = await import('node:path');
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ctx-test-'));
    const fileName = 'UserService.java';
    const content = `import java.sql.*;
public class UserService {
  public User findUser(String name) {
    PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
    stmt.setString(1, name);
    return stmt.executeQuery();
  }
}`;
    await fs.writeFile(path.join(tmpDir, fileName), content);
    const findings = [{ severity: 'high', location: fileName, line: 4, vulnType: 'SQL_INJECTION', confidence: 0.9 }];
    const result = await enhanceFindingsWithContext(findings, tmpDir);
    expect(result[0].confidence).to.be.lessThan(0.9);
    expect(result[0].guardContext.hasGuardPattern).to.be.true;
    await fs.rm(tmpDir, { recursive: true });
  });

  it('keeps high confidence for unguarded code', async () => {
    const fs = await import('node:fs/promises');
    const os = await import('node:os');
    const path = await import('node:path');
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ctx-test-'));
    const fileName = 'Unsafe.java';
    const content = `public class Unsafe {
  public void run(String input) {
    Runtime.getRuntime().exec(input);
  }
}`;
    await fs.writeFile(path.join(tmpDir, fileName), content);
    const findings = [{ severity: 'high', location: fileName, line: 3, vulnType: 'COMMAND_INJECTION', confidence: 0.9 }];
    const result = await enhanceFindingsWithContext(findings, tmpDir);
    expect(result[0].confidence).to.equal(0.9);
    expect(result[0].guardContext.hasGuardPattern).to.be.false;
    await fs.rm(tmpDir, { recursive: true });
  });

  it('reduces confidence for string literal arguments', async () => {
    const fs = await import('node:fs/promises');
    const os = await import('node:os');
    const path = await import('node:path');
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ctx-test-'));
    const fileName = 'Safe.java';
    const content = `public class Safe {
  public void run() {
    "SELECT * FROM users"
  }
}`;
    await fs.writeFile(path.join(tmpDir, fileName), content);
    const findings = [{ severity: 'high', location: fileName, line: 3, vulnType: 'SQL_INJECTION', confidence: 0.9 }];
    const result = await enhanceFindingsWithContext(findings, tmpDir);
    expect(result[0].confidence).to.be.lessThan(0.9);
    expect(result[0].guardContext.hasStringLiteralArg).to.be.true;
    await fs.rm(tmpDir, { recursive: true });
  });
});
