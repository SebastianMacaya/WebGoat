/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
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
    value = {
      "SqlStringInjectionHint.10.1",
      "SqlStringInjectionHint.10.2",
      "SqlStringInjectionHint.10.3",
      "SqlStringInjectionHint.10.4",
      "SqlStringInjectionHint.10.5",
      "SqlStringInjectionHint.10.6"
    })
public class SqlInjectionLesson10 implements AssignmentEndpoint {

  private final LessonDataSource dataSource;

  public SqlInjectionLesson10(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/attack10")
  @ResponseBody
  public AttackResult completed(@RequestParam String action_string) {
    return injectableQueryAvailability(action_string);
  }

  protected AttackResult injectableQueryAvailability(String action) {
    String query = "SELECT * FROM access_log WHERE action LIKE ?";
    try (Connection connection = dataSource.getConnection();
        PreparedStatement statement =
            connection.prepareStatement(
                query, ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY)) {
      statement.setString(1, "%" + action + "%");
      try (ResultSet results = statement.executeQuery()) {
        return failed(this)
            .feedback("sql-injection.10.entries")
            .output(SqlInjectionLesson8.generateTable(results))
            .build();
      }
    } catch (SQLException e) {
      return failed(this).build();
    }
  }
}
