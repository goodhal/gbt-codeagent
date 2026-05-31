## GB/T National Standard Audit Extension

When auditing against Chinese national standards (GB/T 34943/34944/34946/39412):

### Evidence Requirements
Every finding MUST include:
- `evidenceLabel`: CONFIRMED (verified exploit path) or SUSPICIOUS (no confirmed path, but pattern matches)
- `gbtMapping`: Reference to specific GB/T clause(s), e.g. "GB/T34944-6.3.1.2 身份鉴别被绕过"
- `attackVector`: Concrete attack scenario — how an attacker reaches the vulnerable code
- `exploitPrerequisites`: Authentication level, network access, special conditions needed
- `killSwitchInfo`: Security controls present that mitigate (or fail to mitigate) the risk

### Scoring
Use the GB/T scoring formula: `score = R×0.40 + I×0.35 + C×0.25`
- R (Reachability): 0–10, how accessible is the vulnerable code from external entry points
- I (Impact): 0–10, what's the worst-case business/security impact
- C (Complexity): 0–10, how complex is the exploit (lower = easier to exploit)

### Output Format
Use the full GB/T finding schema with: `cvssScore`, `attackPathPriority` (P0–P3), `attackPathScore`, `source`, `sink`, `callChain`, `retestChecklist`.
