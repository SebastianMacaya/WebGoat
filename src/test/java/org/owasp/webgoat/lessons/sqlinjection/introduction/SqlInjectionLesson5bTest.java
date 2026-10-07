/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

public class SqlInjectionLesson5bTest extends LessonTest {

  @Test
  public void numericUserIdStillSearchesAccounts() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/assignment5b")
                .param("login_count", "0")
                .param("userid", "101"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(jsonPath("$.output", containsString("Joe")));
  }

  @Test
  public void injectedUserIdCannotReturnOtherAccounts() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/assignment5b")
                .param("login_count", "0")
                .param("userid", "101 or 1=1"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(jsonPath("$.output", is("Login count and user ID must be numbers")));
  }
}
