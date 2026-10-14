// Planted injection-prone patterns for the PenniLogic/infra#28 SAST rule set (synthetic; never compiled or run).
// Each function is a deliberate positive for one rule in scripts/qa-gates/rules/kotlin.yml.
package pennilogic.qagates.planted

import java.sql.Connection

fun plantedSqlTemplate(connection: Connection, accountName: String) {
    connection.createStatement().executeQuery("SELECT id FROM synthetic_accounts WHERE name = '$accountName'")
}

fun plantedSqlConcatenation(connection: Connection, accountName: String) {
    connection.createStatement().executeQuery("SELECT id FROM synthetic_accounts WHERE name = '" + accountName + "'")
}

fun plantedRuntimeExec(archiveName: String) {
    Runtime.getRuntime().exec("tar -tf " + archiveName)
}
