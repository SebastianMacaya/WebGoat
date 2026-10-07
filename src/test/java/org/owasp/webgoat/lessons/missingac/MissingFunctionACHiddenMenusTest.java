/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.WithWebGoatUser;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.owasp.webgoat.container.users.WebGoatUser;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

class MissingFunctionACHiddenMenusTest extends LessonTest {

  @Test
  @WithWebGoatUser(role = WebGoatUser.ROLE_ADMIN)
  void HiddenMenusSuccess() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/access-control/hidden-menu")
                .param("hiddenMenu1", "Users")
                .param("hiddenMenu2", "Config"))
        .andExpect(
            jsonPath(
                "$.feedback",
                CoreMatchers.is(messages.getMessage("access-control.hidden-menus.success"))))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(true)));
  }

  @Test
  @WithWebGoatUser(role = WebGoatUser.ROLE_ADMIN)
  void HiddenMenusClose() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/access-control/hidden-menu")
                .param("hiddenMenu1", "Config")
                .param("hiddenMenu2", "Users"))
        .andExpect(
            jsonPath(
                "$.feedback",
                CoreMatchers.is(messages.getMessage("access-control.hidden-menus.close"))))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  @WithWebGoatUser(role = WebGoatUser.ROLE_ADMIN)
  void HiddenMenusFailure() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/access-control/hidden-menu")
                .param("hiddenMenu1", "Foo")
                .param("hiddenMenu2", "Bar"))
        .andExpect(
            jsonPath(
                "$.feedback",
                CoreMatchers.is(messages.getMessage("access-control.hidden-menus.failure"))))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  void ordinaryUserCannotGuessHiddenMenuLabels() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/access-control/hidden-menu")
                .param("hiddenMenu1", "Users")
                .param("hiddenMenu2", "Config"))
        .andExpect(status().isForbidden());
  }

  @Test
  void ordinaryUserDoesNotReceiveAdminMenuMarkup() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.get("/MissingFunctionAC.lesson.lesson"))
        .andExpect(status().isOk())
        .andExpect(content().string(not(containsString("access-control/users-admin-fix"))));
  }

  @Test
  @WithWebGoatUser(role = WebGoatUser.ROLE_ADMIN)
  void administratorReceivesAdminMenuMarkup() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.get("/MissingFunctionAC.lesson.lesson"))
        .andExpect(status().isOk())
        .andExpect(content().string(containsString("access-control/users-admin-fix")));
  }
}
