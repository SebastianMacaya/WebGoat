/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.advanced;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

class SqlInjectionChallengeTest extends LessonTest {

  @Autowired private LessonDataSource dataSource;

  @Test
  void registrationTreatsSqlSyntaxAsLiteralUsername() throws Exception {
    String username = "tom' OR '1'='1";

    mockMvc
        .perform(
            MockMvcRequestBuilders.put("/SqlInjectionAdvanced/register")
                .param("username_reg", username)
                .param("email_reg", "literal@example.org")
                .param("password_reg", "safe-password"))
        .andExpect(status().isOk());

    try (var connection = dataSource.getConnection();
        var statement =
            connection.prepareStatement(
                "select email, password from sql_challenge_users where userid = ?")) {
      statement.setString(1, username);
      try (var result = statement.executeQuery()) {
        assertTrue(result.next());
        assertEquals("literal@example.org", result.getString("email"));
        assertEquals("safe-password", result.getString("password"));
      }
    }
  }
}
