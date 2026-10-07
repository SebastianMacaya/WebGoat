/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.xss;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

class CrossSiteScriptingLesson5aTest extends LessonTest {

  @Test
  void formerScriptSolutionIsOnlyDisplayedAsText() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/CrossSiteScripting/attack5a")
                .param("QTY1", "1")
                .param("QTY2", "1")
                .param("QTY3", "1")
                .param("QTY4", "1")
                .param("field1", "<script>alert('XSS')</script>")
                .param("field2", "111"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(jsonPath("$.output", containsString("&lt;script&gt;")))
        .andExpect(jsonPath("$.output", not(containsString("<script>"))));
  }

  @Test
  void rendersCreditCardAsTextWithoutExecutingMarkup() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/CrossSiteScripting/attack5a")
                .param("QTY1", "1")
                .param("QTY2", "1")
                .param("QTY3", "1")
                .param("QTY4", "1")
                .param("field1", "<img src=x onerror=alert(1)>")
                .param("field2", "111"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(jsonPath("$.output", containsString("&lt;img src=x onerror=alert(1)&gt;")))
        .andExpect(jsonPath("$.output", not(containsString("<img"))));
  }

  @Test
  void keepsOrdinaryCheckoutOutput() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/CrossSiteScripting/attack5a")
                .param("QTY1", "1")
                .param("QTY2", "0")
                .param("QTY3", "0")
                .param("QTY4", "0")
                .param("field1", "4111 1111 1111 1111")
                .param("field2", "111"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(jsonPath("$.output", containsString("4111 1111 1111 1111")))
        .andExpect(jsonPath("$.output", containsString("$69.99")));
  }
}
