/*
 * SPDX-FileCopyrightText: Copyright © 2016 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import java.sql.*;
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
      "SqlStringInjectionHint5b1",
      "SqlStringInjectionHint5b2",
      "SqlStringInjectionHint5b3",
      "SqlStringInjectionHint5b4"
    })
public class SqlInjectionLesson5b implements AssignmentEndpoint {

  private final LessonDataSource dataSource;

  public SqlInjectionLesson5b(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/assignment5b")
  @ResponseBody
  public AttackResult completed(@RequestParam String userid, @RequestParam String login_count) {
    return injectableQuery(login_count, userid);
  }

  protected AttackResult injectableQuery(String login_count, String accountName) {
    int count;
    int userId;
    try {
      count = Integer.parseInt(login_count);
      userId = Integer.parseInt(accountName);
    } catch (NumberFormatException e) {
      return failed(this).output("Login count and user ID must be numbers").build();
    }

    String queryString = "SELECT * FROM user_data WHERE Login_Count = ? and userid = ?";
    try (Connection connection = dataSource.getConnection();
        PreparedStatement query =
            connection.prepareStatement(
                queryString, ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY)) {
      query.setInt(1, count);
      query.setInt(2, userId);
      try (ResultSet results = query.executeQuery()) {
        if (results.first()) {
          return failed(this)
              .output(SqlInjectionLesson5a.writeTable(results, results.getMetaData()))
              .build();
        }
        return failed(this).feedback("sql-injection.5b.no.results").build();
      }
    } catch (SQLException e) {
      return failed(this).output("Unable to search accounts").build();
    }
  }
}
