/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

public class SqlInjectionLesson5Test extends LessonTest {

  @Autowired private LessonDataSource dataSource;

  @Test
  public void grantAttemptIsRejectedAndPrivilegesRemainUnchanged() throws Exception {
    int grantsBefore = unauthorizedGrants();
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack5")
                .param("query", "grant select on grant_rights to unauthorized_user"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));

    assertEquals(grantsBefore, unauthorizedGrants());
  }

  @Test
  public void differentTableShouldNotSolveIt() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack5")
                .param("query", "grant select on users to unauthorized_user"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  public void noGrantShouldNotSolveIt() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack5")
                .param("query", "select * from grant_rights"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  public void emptyQueryIsRejected() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.post("/SqlInjection/attack5"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  private int unauthorizedGrants() throws SQLException {
    try (Connection connection = dataSource.getConnection();
        PreparedStatement statement =
            connection.prepareStatement(
                "SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLE_PRIVILEGES "
                    + "WHERE TABLE_NAME = ? AND GRANTEE = ?")) {
      statement.setString(1, "GRANT_RIGHTS");
      statement.setString(2, "UNAUTHORIZED_USER");
      try (ResultSet results = statement.executeQuery()) {
        results.next();
        return results.getInt(1);
      }
    }
  }
}
