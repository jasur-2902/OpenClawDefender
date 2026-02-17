/**
 * Example MCP server with full ClawDefender Level 3 integration.
 *
 * Exposes file-operation tools (read, write, list) and demonstrates
 * every ClawDefender security checkpoint:
 *
 *   1. checkIntent       -- before performing any action
 *   2. requestPermission -- before writes and other sensitive operations
 *   3. reportAction      -- after every action completes
 *
 * Run with:
 *   npx tsx server.ts
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import * as fs from "node:fs/promises";
import * as path from "node:path";

// ── ClawDefender SDK ──────────────────────────────────────────────────────
// If ClawDefender is not installed, the server functions normally (fail-open).
let claw: any = null;

try {
  const sdk = await import("@clawdefender/sdk");
  claw = new sdk.ClawDefenderClient();
} catch {
  // ClawDefender SDK not available -- server runs without guardrails.
}

// ── Server setup ──────────────────────────────────────────────────────────

const server = new Server(
  { name: "example-file-operations-ts", version: "0.1.0" },
  { capabilities: { tools: {} } }
);

// ── Tool listing ──────────────────────────────────────────────────────────

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "read_file",
      description: "Read the contents of a file",
      inputSchema: {
        type: "object" as const,
        properties: {
          path: { type: "string", description: "File path to read" },
        },
        required: ["path"],
      },
    },
    {
      name: "write_file",
      description: "Write content to a file",
      inputSchema: {
        type: "object" as const,
        properties: {
          path: { type: "string", description: "File path to write" },
          content: { type: "string", description: "Content to write" },
        },
        required: ["path", "content"],
      },
    },
    {
      name: "list_directory",
      description: "List files in a directory",
      inputSchema: {
        type: "object" as const,
        properties: {
          path: { type: "string", description: "Directory path" },
        },
        required: ["path"],
      },
    },
  ],
}));

// ── Tool execution ────────────────────────────────────────────────────────

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  switch (name) {
    case "read_file":
      return readFile(args!.path as string);
    case "write_file":
      return writeFile(args!.path as string, args!.content as string);
    case "list_directory":
      return listDirectory(args!.path as string);
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
});

// ── Tool implementations with ClawDefender checkpoints ────────────────────

async function readFile(filePath: string) {
  // CHECKPOINT 1: Check intent before doing anything.
  if (claw) {
    const intent = await claw.checkIntent({
      description: `Read file: ${filePath}`,
      actionType: "file_read",
      target: filePath,
      reason: "User requested file contents",
    });
    if (!intent.allowed) {
      return {
        content: [{ type: "text", text: `Blocked by policy: ${intent.explanation}` }],
      };
    }
  }

  // Perform the action.
  let content: string;
  let result: "success" | "failure";
  try {
    content = await fs.readFile(filePath, "utf-8");
    result = "success";
  } catch (err) {
    content = `Error reading file: ${err}`;
    result = "failure";
  }

  // CHECKPOINT 3: Report what happened.
  if (claw) {
    await claw.reportAction({
      description: `Read file: ${filePath}`,
      actionType: "file_read",
      target: filePath,
      result,
    });
  }

  return { content: [{ type: "text", text: content }] };
}

async function writeFile(filePath: string, content: string) {
  // CHECKPOINT 1: Check intent.
  if (claw) {
    const intent = await claw.checkIntent({
      description: `Write file: ${filePath}`,
      actionType: "file_write",
      target: filePath,
      reason: "User requested file write",
    });
    if (!intent.allowed) {
      return {
        content: [{ type: "text", text: `Blocked by policy: ${intent.explanation}` }],
      };
    }
  }

  // CHECKPOINT 2: Request explicit permission for write operations.
  if (claw) {
    const perm = await claw.requestPermission({
      resource: filePath,
      operation: "write",
      justification: `Writing ${content.length} bytes to ${filePath}`,
    });
    if (!perm.granted) {
      return {
        content: [{ type: "text", text: "Permission denied by user" }],
      };
    }
  }

  // Perform the action.
  let msg: string;
  let result: "success" | "failure";
  try {
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    await fs.writeFile(filePath, content, "utf-8");
    msg = `Wrote ${content.length} bytes to ${filePath}`;
    result = "success";
  } catch (err) {
    msg = `Error writing file: ${err}`;
    result = "failure";
  }

  // CHECKPOINT 3: Report the outcome.
  if (claw) {
    await claw.reportAction({
      description: `Write file: ${filePath}`,
      actionType: "file_write",
      target: filePath,
      result,
    });
  }

  return { content: [{ type: "text", text: msg }] };
}

async function listDirectory(dirPath: string) {
  if (claw) {
    const intent = await claw.checkIntent({
      description: `List directory: ${dirPath}`,
      actionType: "file_read",
      target: dirPath,
      reason: "User requested directory listing",
    });
    if (!intent.allowed) {
      return {
        content: [{ type: "text", text: `Blocked by policy: ${intent.explanation}` }],
      };
    }
  }

  let content: string;
  let result: "success" | "failure";
  try {
    const entries = await fs.readdir(dirPath);
    content = entries.sort().join("\n");
    result = "success";
  } catch (err) {
    content = `Error listing directory: ${err}`;
    result = "failure";
  }

  if (claw) {
    await claw.reportAction({
      description: `List directory: ${dirPath}`,
      actionType: "file_read",
      target: dirPath,
      result,
    });
  }

  return { content: [{ type: "text", text: content }] };
}

// ── Start the server ──────────────────────────────────────────────────────

const transport = new StdioServerTransport();
await server.connect(transport);
