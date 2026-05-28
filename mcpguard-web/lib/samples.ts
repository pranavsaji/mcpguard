/** Sample MCP configs for the dashboard. Files live in /public/samples and are
 *  fetched on demand; this list drives the picker. */

export interface SampleEntry {
  id: string;
  label: string;
  hint: string;
  /** Rough expectation, shown as a chip. */
  expect: "clean" | "findings";
}

export const SAMPLES: SampleEntry[] = [
  {
    id: "01-real-official-servers",
    label: "Real official servers",
    hint: "Canonical Claude Desktop config (filesystem, github, brave…) launched unpinned",
    expect: "findings",
  },
  {
    id: "02-best-practice-pinned",
    label: "Best practice (pinned)",
    hint: "Same servers, pinned versions + ${ENV} secrets — should pass",
    expect: "clean",
  },
  {
    id: "03-hardcoded-secrets",
    label: "Hardcoded secrets",
    hint: "Live GitHub / Anthropic / AWS keys pasted into env",
    expect: "findings",
  },
  {
    id: "04-remote-fetch-launch",
    label: "Remote fetch-and-run",
    hint: "curl | bash and install-from-git launch patterns",
    expect: "findings",
  },
  {
    id: "05-tool-poisoning-manifest",
    label: "Tool poisoning",
    hint: "Enumerated manifest with injected + hidden instructions",
    expect: "findings",
  },
  {
    id: "06-excessive-agency-manifest",
    label: "Excessive agency",
    hint: "Over-powered tools: shell, delete, raw SQL, arbitrary HTTP",
    expect: "findings",
  },
];

export async function loadSampleText(id: string): Promise<string> {
  const res = await fetch(`/samples/${id}.json`);
  if (!res.ok) throw new Error(`Failed to load sample ${id}`);
  return res.text();
}
