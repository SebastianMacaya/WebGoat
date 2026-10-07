/*
 * SPDX-FileCopyrightText: Copyright © 2020 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.mitigation;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

public class SqlOnlyInputValidationOnKeywordsTest extends LessonTest {

  @Test
  public void nestedKeywordsCannotInjectSql() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlOnlyInputValidationOnKeywords/attack")
                .param(
                    "userid_sql_only_input_validation_on_keywords",
                    "Smith';SESELECTLECT/**/*/**/FRFROMOM/**/user_system_data;--"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(content().string(not(containsString("passW0rD"))));
  }

  @Test
  public void sqlKeywordsAreTreatedAsSurnameText() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlOnlyInputValidationOnKeywords/attack")
                .param(
                    "userid_sql_only_input_validation_on_keywords",
                    "Smith';SELECT/**/*/**/from/**/user_system_data;--"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(content().string(not(containsString("passW0rD"))));
  }

  @Test
  public void plainSurnameStillReturnsMatchingUsers() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlOnlyInputValidationOnKeywords/attack")
                .param("userid_sql_only_input_validation_on_keywords", "Smith"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(jsonPath("$.output", containsString("Smith")));
  }

  @Test
  public void spacesRemainRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlOnlyInputValidationOnKeywords/attack")
                .param("userid_sql_only_input_validation_on_keywords", "Smith Jones"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", containsString("not allowed")));
  }
}
