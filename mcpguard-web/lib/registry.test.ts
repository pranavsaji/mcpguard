import { describe, expect, it } from "vitest";
import { kindOf, shortKey, synthesizeConfig, toPublicServer, type RegistryServer } from "./registry";
import { scanConfigText } from "./scanner/scan";

describe("shortKey", () => {
  it("uses the last path segment and sanitizes it", () => {
    expect(shortKey("io.github.user/my-server")).toBe("my-server");
    expect(shortKey("plain")).toBe("plain");
  });
});

describe("synthesizeConfig", () => {
  it("builds an unpinned npx launch with env refs for an npm package", () => {
    const server: RegistryServer = {
      name: "io.github.acme/fs",
      packages: [
        {
          registryType: "npm",
          identifier: "@acme/fs-mcp",
          version: "1.2.3",
          runtimeArguments: [{ type: "positional", value: "-y" }],
          environmentVariables: [{ name: "API_KEY", isSecret: true }],
        },
      ],
    };
    const cfg = JSON.parse(synthesizeConfig(server));
    const entry = cfg.mcpServers.fs;
    expect(entry.command).toBe("npx");
    expect(entry.args).toEqual(["-y", "@acme/fs-mcp"]);
    expect(entry.env).toEqual({ API_KEY: "${API_KEY}" }); // reference, not a value
  });

  it("uses uvx for pypi and docker for oci", () => {
    const pypi = JSON.parse(
      synthesizeConfig({ name: "x/y", packages: [{ registryType: "pypi", identifier: "y-mcp" }] }),
    );
    expect(pypi.mcpServers.y.command).toBe("uvx");

    const oci = JSON.parse(
      synthesizeConfig({ name: "x/z", packages: [{ registryType: "oci", identifier: "z:latest" }] }),
    );
    expect(oci.mcpServers.z.command).toBe("docker");
    expect(oci.mcpServers.z.args).toEqual(["run", "-i", "--rm", "z:latest"]);
  });

  it("builds a remote url entry when there is no package", () => {
    const cfg = JSON.parse(
      synthesizeConfig({
        name: "x/remote",
        remotes: [{ type: "sse", url: "https://api.example/mcp" }],
      }),
    );
    expect(cfg.mcpServers.remote).toEqual({ url: "https://api.example/mcp", type: "sse" });
  });
});

describe("kindOf", () => {
  it("classifies by package or remote", () => {
    expect(kindOf({ name: "a", packages: [{ registryType: "npm", identifier: "a" }] })).toBe("npm");
    expect(kindOf({ name: "a", remotes: [{ type: "sse", url: "u" }] })).toBe("remote");
    expect(kindOf({ name: "a" })).toBe("unknown");
  });
});

describe("synthesized config is scannable", () => {
  it("an unpinned npm server scans to a SUP01 finding", () => {
    const server: RegistryServer = {
      name: "io.github.acme/tool",
      packages: [{ registryType: "npm", identifier: "@acme/tool" }],
    };
    const pub = toPublicServer(server);
    const report = scanConfigText(pub.configText);
    const ids = report.results.flatMap((r) => r.findings.map((f) => f.rule_id));
    expect(ids).toContain("SUP01");
  });

  it("a remote server scans cleanly (no command to fault)", () => {
    const report = scanConfigText(
      synthesizeConfig({ name: "x/r", remotes: [{ type: "http", url: "https://x/mcp" }] }),
    );
    expect(report.summary.total_findings).toBe(0);
  });
});
