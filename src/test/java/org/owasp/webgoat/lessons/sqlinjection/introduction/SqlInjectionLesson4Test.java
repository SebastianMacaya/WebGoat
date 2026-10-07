/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

public class SqlInjectionLesson4Test extends LessonTest {

  @Autowired private LessonDataSource dataSource;

  @Test
  public void requestedColumnAdditionIsRejected() throws Exception {
    boolean phoneExisted = columnExists("PHONE");
    for (int attempt = 0; attempt < 2; attempt++) {
      mockMvc
          .perform(
              MockMvcRequestBuilders.post("/SqlInjection/attack4")
                  .param("query", "alter table employees add column phone varchar(20)"))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.lessonCompleted", is(false)));
    }

    assertEquals(phoneExisted, columnExists("PHONE"));
  }

  @Test
  public void destructiveAlterDoesNotRemoveExistingColumn() throws Exception {
    assertTrue(columnExists("AUTH_TAN"));
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack4")
                .param("query", "ALTER TABLE employees DROP COLUMN auth_tan"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));

    assertTrue(columnExists("AUTH_TAN"));
  }

  private boolean columnExists(String name) throws SQLException {
    try (Connection connection = dataSource.getConnection();
        ResultSet columns =
            connection.getMetaData().getColumns(null, connection.getSchema(), "EMPLOYEES", name)) {
      return columns.next();
    }
  }
}
