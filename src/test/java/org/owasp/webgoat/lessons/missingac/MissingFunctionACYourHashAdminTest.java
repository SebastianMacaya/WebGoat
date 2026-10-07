/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import static org.owasp.webgoat.lessons.missingac.MissingFunctionAC.PASSWORD_SALT_ADMIN;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.WithWebGoatUser;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.owasp.webgoat.container.users.WebGoatUser;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class MissingFunctionACYourHashAdminTest extends LessonTest {

  @BeforeEach
  public void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  @Test
  @WithWebGoatUser(role = WebGoatUser.ROLE_ADMIN)
  void solve() throws Exception {
    var userHash =
        new DisplayUser(new User("Jerry", "doesnotreallymatter", true), PASSWORD_SALT_ADMIN)
            .getUserHash();
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/access-control/user-hash-fix")
                .param("userHash", userHash))
        .andExpect(status().isOk())
        .andExpect(
            jsonPath(
                "$.feedback",
                CoreMatchers.containsString(
                    "Congrats! You really succeeded when you added the user.")))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(true)));
  }

  @Test
  @WithWebGoatUser(role = WebGoatUser.ROLE_ADMIN)
  void wrongUserHash() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/access-control/user-hash-fix").param("userHash", "wrong"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  void selfCreatedLessonAdminCannotSubmitJerrysHash() throws Exception {
    var userHash =
        new DisplayUser(new User("Jerry", "doesnotreallymatter", true), PASSWORD_SALT_ADMIN)
            .getUserHash();
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/access-control/user-hash-fix")
                .param("userHash", userHash))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }
}
