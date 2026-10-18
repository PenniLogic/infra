// Clean control for the PenniLogic/infra#28 SAST rule set (synthetic; never compiled or run).
// The safe counterparts of PlantedInjection.kt: no rule in scripts/qa-gates/rules/kotlin.yml may match here.
package pennilogic.qagates.planted

import java.sql.Connection

fun controlBoundParameter(connection: Connection, accountName: String) {
    connection.prepareStatement("SELECT id FROM synthetic_accounts WHERE name = ?").use { statement ->
        statement.setString(1, accountName)
        statement.executeQuery()
    }
}

fun controlArgumentList(archiveName: String) {
    ProcessBuilder("tar", "-tf", archiveName).start()
}
