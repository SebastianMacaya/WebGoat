/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.htmltampering;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

class HtmlTamperingTaskTest extends LessonTest {

  @Test
  void acceptsOnlyServerCalculatedTotalForAValidOrder() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/HtmlTampering/task")
                .param("QTY", "2")
                .param("Total", "5999.98"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted").value(false))
        .andExpect(
            jsonPath("$.feedback").value(messages.getMessage("html-tampering.order.accepted")));
  }

  @Test
  void underpricedOrderDoesNotCompleteTheAssignment() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/HtmlTampering/task")
                .param("QTY", "2")
                .param("Total", "1.00"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted").value(false))
        .andExpect(
            jsonPath("$.feedback").value(messages.getMessage("html-tampering.tamper.failure")));
  }

  @Test
  void rejectsNonIntegralOrNegativeQuantity() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/HtmlTampering/task")
                .param("QTY", "0.0001")
                .param("Total", "0.01"))
        .andExpect(status().isBadRequest());
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/HtmlTampering/task")
                .param("QTY", "-1")
                .param("Total", "-2999.99"))
        .andExpect(status().isBadRequest());
  }

  @Test
  void rejectsNonFiniteOrMalformedTotal() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/HtmlTampering/task")
                .param("QTY", "1")
                .param("Total", "NaN"))
        .andExpect(status().isBadRequest());
  }
}
