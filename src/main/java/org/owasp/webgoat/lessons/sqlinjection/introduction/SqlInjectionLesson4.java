/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.util.regex.Pattern;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints(
    value = {"SqlStringInjectionHint4-1", "SqlStringInjectionHint4-2", "SqlStringInjectionHint4-3"})
public class SqlInjectionLesson4 implements AssignmentEndpoint {

  private static final Pattern APPROVED_ALTER =
      Pattern.compile(
          "\\A\\s*ALTER\\s+TABLE\\s+employees\\s+ADD\\s+(?:COLUMN\\s+)?phone\\s+VARCHAR\\s*\\(\\s*20\\s*\\)\\s*;?\\s*\\z",
          Pattern.CASE_INSENSITIVE);

  private final LessonDataSource dataSource;

  public SqlInjectionLesson4(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/attack4")
  @ResponseBody
  public AttackResult completed(@RequestParam String query) {
    return injectableQuery(query);
  }

  protected AttackResult injectableQuery(String query) {
    if (query == null || !APPROVED_ALTER.matcher(query).matches()) {
      return failed(this).build();
    }

    try (Connection connection = dataSource.getConnection()) {
      if (!phoneColumnExists(connection)) {
        try (Statement statement = connection.createStatement()) {
          statement.executeUpdate("ALTER TABLE employees ADD COLUMN phone VARCHAR(20)");
        }
      }
      return phoneColumnExists(connection)
          ? success(this).output("<span class='feedback-positive'>phone</span>").build()
          : failed(this).build();
    } catch (SQLException e) {
      return failed(this).build();
    }
  }

  private boolean phoneColumnExists(Connection connection) throws SQLException {
    try (ResultSet columns =
        connection
            .getMetaData()
            .getColumns(null, connection.getSchema(), "EMPLOYEES", "PHONE")) {
      return columns.next()
          && columns.getInt("DATA_TYPE") == Types.VARCHAR
          && columns.getInt("COLUMN_SIZE") == 20;
    }
  }
}
