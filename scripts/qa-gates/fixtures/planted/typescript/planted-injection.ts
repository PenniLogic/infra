// Planted injection-prone patterns for the PenniLogic/infra#28 SAST rule set (synthetic; never compiled or run).
// Each function is a deliberate positive for one rule in scripts/qa-gates/rules/typescript.yml.
import { exec } from "node:child_process";

interface SyntheticDatabase {
  query(text: string, values?: unknown[]): Promise<unknown>;
}

export async function plantedSqlTemplate(db: SyntheticDatabase, accountName: string): Promise<unknown> {
  return db.query(`SELECT id FROM synthetic_accounts WHERE name = '${accountName}'`);
}

export async function plantedSqlConcatenation(db: SyntheticDatabase, accountName: string): Promise<unknown> {
  return db.query("SELECT id FROM synthetic_accounts WHERE name = '" + accountName + "'");
}

export function plantedShellCommand(archiveName: string): void {
  exec("tar -tf " + archiveName);
}

export function plantedDynamicEval(expression: string): unknown {
  return eval(expression);
}

export function plantedFunctionConstructor(body: string): unknown {
  return new Function(body);
}
