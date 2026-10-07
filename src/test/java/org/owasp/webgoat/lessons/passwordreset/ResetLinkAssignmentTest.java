/*
 * SPDX-FileCopyrightText: Copyright © 2023 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.lessons.passwordreset.ResetLinkAssignment.TOM_EMAIL;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import java.time.Instant;
import org.assertj.core.api.Assertions;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

class ResetLinkAssignmentTest extends LessonTest {

  @Value("${webgoat.url}")
  private String webGoatURL;

  @Value("${webwolf.mail.url}")
  private String webWolfMailURL;

  @Value("${webwolf.host}")
  private String webWolfHost;

  @Value("${webwolf.port}")
  private String webWolfPort;

  @Autowired private ResourceLoader resourceLoader;
  @MockBean private RestTemplate restTemplate;

  @BeforeEach
  public void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
    ResetLinkAssignment.resetLinks.clear();
    ResetLinkAssignment.usersToTomPassword.clear();
  }

  @Test
  void wrongResetLink() throws Exception {
    MvcResult mvcResult =
        mockMvc
            .perform(
                MockMvcRequestBuilders.get("/PasswordReset/reset/reset-password/{link}", "test"))
            .andExpect(status().isOk())
            .andExpect(view().name("lessons/passwordreset/templates/password_link_not_found.html"))
            .andReturn();
    Assertions.assertThat(resourceLoader.getResource(mvcResult.getModelAndView().getViewName()))
        .isNotNull();
  }

  @Test
  void changePasswordWithoutPasswordShouldReturnPasswordForm() throws Exception {
    MvcResult mvcResult =
        mockMvc
            .perform(MockMvcRequestBuilders.post("/PasswordReset/reset/change-password"))
            .andExpect(status().isOk())
            .andExpect(view().name("lessons/passwordreset/templates/password_reset.html"))
            .andReturn();
    Assertions.assertThat(resourceLoader.getResource(mvcResult.getModelAndView().getViewName()))
        .isNotNull();
  }

  @Test
  void changePasswordWithoutLinkShouldReturnPasswordLinkNotFound() throws Exception {
    MvcResult mvcResult =
        mockMvc
            .perform(
                MockMvcRequestBuilders.post("/PasswordReset/reset/change-password")
                    .param("password", "new_password"))
            .andExpect(status().isOk())
            .andExpect(view().name("lessons/passwordreset/templates/password_link_not_found.html"))
            .andReturn();
    Assertions.assertThat(resourceLoader.getResource(mvcResult.getModelAndView().getViewName()))
        .isNotNull();
  }

  @Test
  void knownLinkShouldReturnPasswordResetPage() throws Exception {
    // Create a reset link
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/ForgotPassword/create-password-reset-link")
                .param("email", "test@webgoat.org")
                .header(HttpHeaders.HOST, "attacker.example:9090"))
        .andExpect(status().isOk());
    Assertions.assertThat(ResetLinkAssignment.resetLinks).isNotEmpty();

    // With a known link you should be
    MvcResult mvcResult =
        mockMvc
            .perform(
                MockMvcRequestBuilders.get(
                    "/PasswordReset/reset/reset-password/{link}",
                    ResetLinkAssignment.resetLinks.keySet().iterator().next()))
            .andExpect(status().isOk())
            .andExpect(view().name("lessons/passwordreset/templates/password_reset.html"))
            .andReturn();

    Assertions.assertThat(resourceLoader.getResource(mvcResult.getModelAndView().getViewName()))
        .isNotNull();
  }

  @Test
  void hostHeaderCannotPoisonResetEmail() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/ForgotPassword/create-password-reset-link")
                .param("email", "test@webgoat.org")
                .header(HttpHeaders.HOST, "attacker.example:9090"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));

    String token = ResetLinkAssignment.resetLinks.keySet().iterator().next();
    ArgumentCaptor<PasswordResetEmail> mail = ArgumentCaptor.forClass(PasswordResetEmail.class);
    verify(restTemplate).postForEntity(eq(webWolfMailURL), mail.capture(), eq(Object.class));
    Assertions.assertThat(mail.getValue().getRecipient()).isEqualTo("test");
    Assertions.assertThat(mail.getValue().getContents())
        .contains(webGoatURL + "/PasswordReset/reset/reset-password/" + token)
        .doesNotContain("attacker.example");
  }

  @Test
  void tomRequestUsesTrustedHostAndHisOwnMailbox() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/ForgotPassword/create-password-reset-link")
                .param("email", TOM_EMAIL)
                .header(HttpHeaders.HOST, webWolfHost + ":" + webWolfPort))
        .andExpect(status().isOk());

    String token = ResetLinkAssignment.resetLinks.keySet().iterator().next();
    ArgumentCaptor<PasswordResetEmail> mail = ArgumentCaptor.forClass(PasswordResetEmail.class);
    verify(restTemplate).postForEntity(eq(webWolfMailURL), mail.capture(), eq(Object.class));
    Assertions.assertThat(mail.getValue().getRecipient()).isEqualTo("tom");
    Assertions.assertThat(mail.getValue().getContents())
        .contains(webGoatURL + "/PasswordReset/reset/reset-password/" + token)
        .doesNotContain(webWolfHost + ":" + webWolfPort);
  }

  @Test
  void anotherPersonsLinkCannotChangeTomsPassword() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/ForgotPassword/create-password-reset-link")
                .param("email", "test@webgoat.org"))
        .andExpect(status().isOk());
    String token = ResetLinkAssignment.resetLinks.keySet().iterator().next();

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/reset/change-password")
                .param("resetLink", token)
                .param("password", "newpass"))
        .andExpect(status().isOk())
        .andExpect(view().name("lessons/passwordreset/templates/success.html"));

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/reset/login")
                .param("email", TOM_EMAIL)
                .param("password", "newpass"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
    Assertions.assertThat(ResetLinkAssignment.resetLinks).doesNotContainKey(token);
  }

  @Test
  void tomsLinkChangesHisPasswordOnlyOnce() throws Exception {
    String token = "verified-tom-token";
    ResetLinkAssignment.resetLinks.put(
        token, new ResetLinkAssignment.ResetLink(TOM_EMAIL, Instant.now().plusSeconds(60)));

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/reset/change-password")
                .param("resetLink", token)
                .param("password", "newpass"))
        .andExpect(status().isOk())
        .andExpect(view().name("lessons/passwordreset/templates/success.html"));
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/reset/login")
                .param("email", TOM_EMAIL)
                .param("password", "newpass"))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(true)));

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/reset/change-password")
                .param("resetLink", token)
                .param("password", "otherpass"))
        .andExpect(status().isOk())
        .andExpect(view().name("lessons/passwordreset/templates/password_link_not_found.html"));
  }

  @Test
  void expiredLinkIsRejected() throws Exception {
    ResetLinkAssignment.resetLinks.put(
        "expired", new ResetLinkAssignment.ResetLink(TOM_EMAIL, Instant.now().minusSeconds(1)));

    mockMvc
        .perform(MockMvcRequestBuilders.get("/PasswordReset/reset/reset-password/expired"))
        .andExpect(status().isOk())
        .andExpect(view().name("lessons/passwordreset/templates/password_link_not_found.html"));
    Assertions.assertThat(ResetLinkAssignment.resetLinks).doesNotContainKey("expired");
  }

  @Test
  void failedMailDeliveryDoesNotLeaveAUsableToken() throws Exception {
    when(restTemplate.postForEntity(
            eq(webWolfMailURL), any(PasswordResetEmail.class), eq(Object.class)))
        .thenThrow(new RestClientException("mail unavailable"));

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/ForgotPassword/create-password-reset-link")
                .param("email", "test@webgoat.org"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
    Assertions.assertThat(ResetLinkAssignment.resetLinks).isEmpty();
  }
}
