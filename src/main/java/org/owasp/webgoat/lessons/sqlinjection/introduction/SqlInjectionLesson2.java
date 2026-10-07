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
import java.util.regex.Matcher;
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
    value = {
      "SqlStringInjectionHint2-1",
      "SqlStringInjectionHint2-2",
      "SqlStringInjectionHint2-3",
      "SqlStringInjectionHint2-4"
    })
public class SqlInjectionLesson2 implements AssignmentEndpoint {

  private static final Pattern BY_USER_ID =
      Pattern.compile(
          "\\A\\s*SELECT\\s+department\\s+FROM\\s+employees\\s+WHERE\\s+userid\\s*=\\s*([0-9]{1,6})\\s*;?\\s*\\z",
          Pattern.CASE_INSENSITIVE);
  private static final Pattern BY_LAST_NAME =
      Pattern.compile(
          "\\A\\s*SELECT\\s+department\\s+FROM\\s+employees\\s+WHERE\\s+last_name\\s*=\\s*'([A-Za-z -]{1,20})'\\s*;?\\s*\\z",
          Pattern.CASE_INSENSITIVE);

  private final LessonDataSource dataSource;

  public SqlInjectionLesson2(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/attack2")
  @ResponseBody
  public AttackResult completed(@RequestParam String query) {
    return injectableQuery(query);
  }

  protected AttackResult injectableQuery(String query) {
    if (query == null) {
      return failed(this).feedback("sql-injection.2.failed").build();
    }
    Matcher byUserId = BY_USER_ID.matcher(query);
    Matcher byLastName = BY_LAST_NAME.matcher(query);
    boolean searchByUserId = byUserId.matches();
    if (!searchByUserId && !byLastName.matches()) {
      return failed(this).feedback("sql-injection.2.failed").build();
    }

    String sql =
        searchByUserId
            ? "SELECT department FROM employees WHERE userid = ?"
            : "SELECT department FROM employees WHERE last_name = ?";
    String value = searchByUserId ? byUserId.group(1) : byLastName.group(1);
    try (Connection connection = dataSource.getConnection();
        PreparedStatement statement =
            connection.prepareStatement(sql, TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY)) {
      statement.setString(1, value);
      try (ResultSet results = statement.executeQuery()) {
        if (results.first() && "Marketing".equals(results.getString("department"))) {
          return success(this)
              .feedback("sql-injection.2.success")
              .output(SqlInjectionLesson8.generateTable(results))
              .build();
        }
        return failed(this).feedback("sql-injection.2.failed").build();
      }
    } catch (SQLException e) {
      return failed(this).feedback("sql-injection.2.failed").build();
    }
  }
}
