/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
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

/**
 * @author Benedikt Stuhrmann
 * @since 11/07/18.
 */
public class SqlInjectionLesson10Test extends LessonTest {

  @Autowired private LessonDataSource dataSource;

  @Test
  public void emptySearchStillReturnsEntries() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.post("/SqlInjection/attack10").param("action_string", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("sql-injection.10.entries"))));
  }

  @Test
  public void matchingActionIsStillReturned() throws Exception {
    String action = "attack10-normal-search-marker";
    insertAction(action);
    try {
      mockMvc
          .perform(
              MockMvcRequestBuilders.post("/SqlInjection/attack10")
                  .param("action_string", "normal-search"))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.lessonCompleted", is(false)))
          .andExpect(jsonPath("$.output", containsString(action)));
    } finally {
      deleteAction(action);
    }
  }

  @Test
  public void dropTablePayloadCannotRemoveAccessLog() throws Exception {
    int originalRowCount = getAccessLogRowCount();
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack10")
                .param("action_string", "%'; DROP TABLE access_log;--"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("sql-injection.10.entries"))));
    assertEquals(originalRowCount, getAccessLogRowCount());
  }

  private void insertAction(String action) throws SQLException {
    try (Connection connection = dataSource.getConnection();
        PreparedStatement statement =
            connection.prepareStatement("INSERT INTO access_log (time, action) VALUES (?, ?)")) {
      statement.setString(1, "test");
      statement.setString(2, action);
      statement.executeUpdate();
    }
  }

  private void deleteAction(String action) throws SQLException {
    try (Connection connection = dataSource.getConnection();
        PreparedStatement statement =
            connection.prepareStatement("DELETE FROM access_log WHERE action = ?")) {
      statement.setString(1, action);
      statement.executeUpdate();
    }
  }

  private int getAccessLogRowCount() throws SQLException {
    try (Connection connection = dataSource.getConnection();
        PreparedStatement statement = connection.prepareStatement("SELECT COUNT(*) FROM access_log");
        ResultSet result = statement.executeQuery()) {
      result.next();
      return result.getInt(1);
    }
  }
}
