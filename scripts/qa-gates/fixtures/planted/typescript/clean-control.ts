// Clean control for the PenniLogic/infra#28 SAST rule set (synthetic; never compiled or run).
// The safe counterparts of planted-injection.ts: no rule in scripts/qa-gates/rules/typescript.yml may match here.
import { execFile } from "node:child_process";

interface SyntheticDatabase {
  query(text: string, values?: unknown[]): Promise<unknown>;
}

export async function controlBoundParameter(db: SyntheticDatabase, accountName: string): Promise<unknown> {
  return db.query("SELECT id FROM synthetic_accounts WHERE name = $1", [accountName]);
}

export function controlArgumentList(archiveName: string): void {
  execFile("tar", ["-tf", archiveName]);
}

export function controlRegexExec(value: string): boolean {
  return /^[a-z]+$/.exec(value) !== null;
}
