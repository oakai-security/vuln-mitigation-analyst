# vuln-mitigation-analyst

Autonomous vulnerability mitigation micro-agent synthesizing Falco runtime eBPF compensating controls.

Part of the **Oakai Security** vulnerability exception and risk governance multi-agent pipeline.

## Overview

When a vulnerability cannot be immediately patched (e.g. no upstream Debian fix) and cannot be purged (due to system dependencies), and automated exception approval is blocked due to high exploit probability (EPSS >= 0.05), the `vuln-mitigation-analyst` establishes **Compensating Controls**:

1. **Target Discovery**: Discovers associated binaries, shared libraries, and attack vectors.
2. **Rule Synthesis**: Generates scoped Falco eBPF runtime detection rules.
3. **Rule Validation**: Verifies Falco rule syntax against eBPF engine standards.
4. **Deployment**: Deploys rule to `/etc/falco/rules.d/` and tests runtime responsiveness.
5. **Governance Relay**: Updates exception ticket with active compensating control status and re-routes to `vuln-exception-approver` for conditional 30-day approval.

## IPC Architecture

- **UDS Listener**: `/run/oakai/mitigate.sock`
- **Downstream Route**: `/run/oakai/approve.sock`
