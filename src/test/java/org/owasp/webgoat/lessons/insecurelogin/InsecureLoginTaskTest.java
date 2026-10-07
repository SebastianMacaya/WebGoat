/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.insecurelogin;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

class InsecureLoginTaskTest extends LessonTest {

  @Test
  void hardCodedCredentialsCannotCompleteTheAssignment() throws Exception {
    MockHttpSession session = new MockHttpSession();
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/InsecureLogin/task")
                .session(session)
                .param("username", "CaptainJack")
                .param("password", "BlackPearl"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted").value(false));

    mockMvc
        .perform(MockMvcRequestBuilders.post("/InsecureLogin/login").session(session))
        .andExpect(status().isAccepted());
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/InsecureLogin/task")
                .session(session)
                .param("username", "CaptainJack")
                .param("password", "BlackPearl"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted").value(false));
  }

  @Test
  void serverSideSessionCanConfirmLoginWithoutSendingCredentials() throws Exception {
    MockHttpSession session = new MockHttpSession();
    mockMvc
        .perform(MockMvcRequestBuilders.post("/InsecureLogin/login").session(session))
        .andExpect(status().isAccepted());
    mockMvc
        .perform(MockMvcRequestBuilders.post("/InsecureLogin/task").session(session))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted").value(true));
  }

  @Test
  void loginEndpointRejectsCredentialPayloads() throws Exception {
    MockHttpSession session = new MockHttpSession();
    mockMvc
        .perform(MockMvcRequestBuilders.post("/InsecureLogin/login").session(session))
        .andExpect(status().isAccepted());
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/InsecureLogin/login")
                .session(session)
                .contentType("application/json")
                .content("{\"username\":\"CaptainJack\",\"password\":\"BlackPearl\"}"))
        .andExpect(status().isBadRequest());
    mockMvc
        .perform(MockMvcRequestBuilders.post("/InsecureLogin/task").session(session))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted").value(false));
  }

  @Test
  void credentialPayloadCannotConfirmAnExistingSession() throws Exception {
    MockHttpSession session = new MockHttpSession();
    mockMvc
        .perform(MockMvcRequestBuilders.post("/InsecureLogin/login").session(session))
        .andExpect(status().isAccepted());
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/InsecureLogin/task")
                .session(session)
                .contentType("application/json")
                .content("{\"username\":\"CaptainJack\",\"password\":\"BlackPearl\"}"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted").value(false));
  }

  @Test
  void browserScriptContainsNoSecret() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.get("/lesson_js/insecure-login-session.js"))
        .andExpect(status().isOk())
        .andExpect(content().string(not(containsString("BlackPearl"))))
        .andExpect(content().string(not(containsString("CaptainJack"))));
  }
}
