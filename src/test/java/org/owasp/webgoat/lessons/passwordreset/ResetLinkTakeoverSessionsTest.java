/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import java.net.URI;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.owasp.webgoat.container.users.UserProgress;
import org.owasp.webgoat.container.users.UserProgressRepository;
import org.owasp.webgoat.container.users.WebGoatUser;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.client.RestTemplate;

class ResetLinkTakeoverSessionsTest extends LessonTest {

  private static final String RESET_PATH = "/PasswordReset/reset/reset-password/";
  private static final String TOM_EMAIL = "tom@webgoat-cloud.org";
  private static final String NEW_PASSWORD = "TomProof8";

  @Value("${webwolf.url}") private String webWolfUrl;
  @MockBean private RestTemplate restTemplate;
  @MockBean private UserProgressRepository userProgressRepository;
  private final Map<String, UserProgress> progressByUsername = new ConcurrentHashMap<>();

  @BeforeEach
  void prepareTwoSessions() {
    mockMvc = MockMvcBuilders.webAppContextSetup(wac).apply(springSecurity()).build();
    ResetLinkAssignment.resetLinks.clear();
    ResetLinkAssignment.resetPasswordsByEmail.clear();
    progressByUsername.clear();
    // The two fixture principals have independent lesson progress without persisting shared
    // Course assignments a second time through JPA.
    when(userProgressRepository.findByUser(anyString()))
        .thenAnswer(invocation ->
            progressByUsername.computeIfAbsent(invocation.getArgument(0), UserProgress::new));
    when(userProgressRepository.save(any(UserProgress.class)))
        .thenAnswer(invocation -> invocation.getArgument(0));
  }

  @Test
  void wolfSeesTomsTokenButOnlyTomCanUseIt() throws Exception {
    WebGoatUser attacker = new WebGoatUser("attacker", "password");
    WebGoatUser tom = new WebGoatUser("tom", "password");
    MockHttpSession attackerSession = new MockHttpSession();
    MockHttpSession tomSession = new MockHttpSession();

    mockMvc
        .perform(
            post("/PasswordReset/ForgotPassword/create-password-reset-link")
                .session(attackerSession)
                .with(user(attacker))
                .header(HttpHeaders.HOST, URI.create(webWolfUrl).getAuthority())
                .param("email", TOM_EMAIL))
        .andExpect(status().isOk());

    // Read the UUID from the simulated WebWolf request, never from the token store.
    ArgumentCaptor<String> visitedUrl = ArgumentCaptor.forClass(String.class);
    verify(restTemplate).getForEntity(visitedUrl.capture(), eq(String.class));
    URI leakedLink = URI.create(visitedUrl.getValue());
    assertThat(leakedLink.getPath()).contains(RESET_PATH);
    String token = leakedLink.getPath().substring(leakedLink.getPath().lastIndexOf('/') + 1);
    assertThat(UUID.fromString(token).toString()).isEqualTo(token);

    mockMvc
        .perform(
            get(RESET_PATH + token).session(attackerSession).with(user(attacker)))
        .andExpect(status().isOk())
        .andExpect(view().name("lessons/passwordreset/templates/password_reset.html"));

    String attackerResult =
        mockMvc
            .perform(
                post("/PasswordReset/reset/change-password")
                    .session(attackerSession)
                    .with(user(attacker))
                    .param("resetLink", token)
                    .param("password", NEW_PASSWORD))
            .andExpect(status().isOk())
            .andReturn()
            .getModelAndView()
            .getViewName();
    assertThat(attackerResult).isNotEqualTo("lessons/passwordreset/templates/success.html");

    mockMvc
        .perform(
            post("/PasswordReset/reset/login")
                .session(attackerSession)
                .with(user(attacker))
                .param("email", TOM_EMAIL)
                .param("password", NEW_PASSWORD))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));

    mockMvc
        .perform(get(RESET_PATH + token).session(tomSession).with(user(tom)))
        .andExpect(status().isOk())
        .andExpect(view().name("lessons/passwordreset/templates/password_reset.html"));
    mockMvc
        .perform(
            post("/PasswordReset/reset/change-password")
                .session(tomSession)
                .with(user(tom))
                .param("resetLink", token)
                .param("password", NEW_PASSWORD))
        .andExpect(status().isOk())
        .andExpect(view().name("lessons/passwordreset/templates/success.html"));

    mockMvc
        .perform(
            post("/PasswordReset/reset/login")
                .session(tomSession)
                .with(user(tom))
                .param("email", TOM_EMAIL)
                .param("password", NEW_PASSWORD))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(true)));

    mockMvc
        .perform(
            post("/PasswordReset/reset/change-password")
                .session(tomSession)
                .with(user(tom))
                .param("resetLink", token)
                .param("password", "Other123"))
        .andExpect(status().isOk())
        .andExpect(view().name("lessons/passwordreset/templates/password_link_not_found.html"));
  }
}
