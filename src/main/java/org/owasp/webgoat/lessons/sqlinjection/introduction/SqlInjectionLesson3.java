/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static java.sql.ResultSet.CONCUR_READ_ONLY;
import static java.sql.ResultSet.TYPE_SCROLL_INSENSITIVE;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
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
@AssignmentHints(value = {"SqlStringInjectionHint3-1", "SqlStringInjectionHint3-2"})
public class SqlInjectionLesson3 implements AssignmentEndpoint {

  private static final Pattern APPROVED_UPDATE =
      Pattern.compile(
          "\\A\\s*UPDATE\\s+employees\\s+SET\\s+department\\s*=\\s*'Sales'\\s+WHERE\\s+last_name\\s*=\\s*'Barnett'\\s*;?\\s*\\z",
          Pattern.CASE_INSENSITIVE);

  private final LessonDataSource dataSource;

  public SqlInjectionLesson3(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/attack3")
  @ResponseBody
  public AttackResult completed(@RequestParam String query) {
    return injectableQuery(query);
  }

  protected AttackResult injectableQuery(String query) {
    if (query == null || !APPROVED_UPDATE.matcher(query).matches()) {
      return failed(this).build();
    }

    try (Connection connection = dataSource.getConnection();
        PreparedStatement update =
            connection.prepareStatement(
                "UPDATE employees SET department = ? WHERE last_name = ?");
        PreparedStatement check =
            connection.prepareStatement(
                "SELECT first_name, last_name, department FROM employees WHERE last_name = ?",
                TYPE_SCROLL_INSENSITIVE,
                CONCUR_READ_ONLY)) {
      update.setString(1, "Sales");
      update.setString(2, "Barnett");
      update.executeUpdate();

      check.setString(1, "Barnett");
      try (ResultSet results = check.executeQuery()) {
        if (results.first() && "Sales".equals(results.getString("department"))) {
          return success(this).output(SqlInjectionLesson8.generateTable(results)).build();
        }
      }
      return failed(this).build();
    } catch (SQLException e) {
      return failed(this).build();
    }
  }
}
