/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
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

public class SqlInjectionLesson3Test extends LessonTest {

  @Autowired private LessonDataSource dataSource;

  @Test
  public void expectedDepartmentChangeStillWorks() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack3")
                .param(
                    "query",
                    "update employees set department='Sales' where last_name='Barnett'"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(true)));

    assertEquals("Sales", departmentForBarnett());
  }

  @Test
  public void arbitraryUpdateDoesNotChangeSalary() throws Exception {
    int salaryBefore = salaryForSmith();
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack3")
                .param("query", "UPDATE employees SET salary=999999 WHERE last_name='Smith'"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));

    assertEquals(salaryBefore, salaryForSmith());
  }

  private String departmentForBarnett() throws SQLException {
    try (Connection connection = dataSource.getConnection();
        PreparedStatement statement =
            connection.prepareStatement("SELECT department FROM employees WHERE last_name = ?")) {
      statement.setString(1, "Barnett");
      try (ResultSet results = statement.executeQuery()) {
        results.next();
        return results.getString(1);
      }
    }
  }

  private int salaryForSmith() throws SQLException {
    try (Connection connection = dataSource.getConnection();
        PreparedStatement statement =
            connection.prepareStatement("SELECT salary FROM employees WHERE last_name = ?")) {
      statement.setString(1, "Smith");
      try (ResultSet results = statement.executeQuery()) {
        results.next();
        return results.getInt(1);
      }
    }
  }
}
