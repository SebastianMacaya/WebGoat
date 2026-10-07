/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.owasp.webgoat.container.session.LessonSession;
import org.owasp.webgoat.container.users.WebGoatUser;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.web.server.ResponseStatusException;

class IDORAccessControlTest extends LessonTest {

  @Test
  void profileEndpointsRequireLessonAuthentication() throws Exception {
    MockHttpSession session = new MockHttpSession();
    mockMvc
        .perform(MockMvcRequestBuilders.get("/IDOR/profile").session(session))
        .andExpect(status().isUnauthorized());
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/IDOR/diff-attributes")
                .session(session)
                .param("attributes", "userId,role"))
        .andExpect(status().isUnauthorized());
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/IDOR/profile/alt-path")
                .session(session)
                .param("url", "WebGoat/IDOR/profile/2342384"))
        .andExpect(status().isUnauthorized());
    mockMvc
        .perform(MockMvcRequestBuilders.get("/IDOR/profile/2342388").session(session))
        .andExpect(status().isUnauthorized());
    mockMvc
        .perform(
            MockMvcRequestBuilders.put("/IDOR/profile/2342388")
                .session(session)
                .contentType("application/json")
                .content("{\"userId\":\"2342388\",\"color\":\"red\",\"role\":1}"))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void ownProfileRemainsAvailableWithoutHiddenMetadata() throws Exception {
    MockHttpSession session = new MockHttpSession();
    loginTom(session);

    mockMvc
        .perform(MockMvcRequestBuilders.get("/IDOR/profile").session(session))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.name").value("Tom Cat"))
        .andExpect(jsonPath("$.userId").doesNotExist())
        .andExpect(jsonPath("$.role").doesNotExist());
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/IDOR/diff-attributes")
                .session(session)
                .param("attributes", "userId,role"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted").value(false));
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/IDOR/profile/alt-path")
                .session(session)
                .param("url", "WebGoat/IDOR/profile/2342384"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted").value(false))
        .andExpect(jsonPath("$.output", not(containsString("userId"))));
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/IDOR/profile/alt-path")
                .session(session)
                .param("url", "WebGoat/IDOR/profile/2342384/2342388"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted").value(false));
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/IDOR/profile/alt-path")
                .session(session)
                .param("url", "WebGoat/IDOR/profile/2342388"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted").value(false));
    mockMvc
        .perform(MockMvcRequestBuilders.get("/IDOR/profile/2342384").session(session))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.output", not(containsString("role"))));
    mockMvc
        .perform(MockMvcRequestBuilders.get("/IDOR/profile/2342388").session(session))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted").value(false));
  }

  @Test
  void ownProfileEditCannotChangeRoleOrAnotherProfile() throws Exception {
    MockHttpSession session = new MockHttpSession();
    loginTom(session);

    mockMvc
        .perform(
            MockMvcRequestBuilders.put("/IDOR/profile/2342388")
                .session(session)
                .contentType("application/json")
                .content("{\"userId\":\"2342388\",\"color\":\"red\",\"role\":1}"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted").value(false));
    mockMvc
        .perform(
            MockMvcRequestBuilders.put("/IDOR/profile/2342384")
                .session(session)
                .contentType("application/json")
                .content("{\"userId\":\"2342388\",\"color\":\"blue\"}"))
        .andExpect(status().isBadRequest());
    mockMvc
        .perform(
            MockMvcRequestBuilders.put("/IDOR/profile/2342384")
                .session(session)
                .contentType("application/json")
                .content(
                    "{\"userId\":\"2342384\",\"color\":\"blue\",\"size\":\"medium\",\"role\":1}"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted").value(false))
        .andExpect(jsonPath("$.output", not(containsString("role"))));
    mockMvc
        .perform(MockMvcRequestBuilders.get("/IDOR/profile").session(session))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.color").value("blue"))
        .andExpect(jsonPath("$.size").value("medium"))
        .andExpect(jsonPath("$.role").doesNotExist());
  }

  @Test
  void failedLoginRevokesExistingLessonAuthentication() throws Exception {
    MockHttpSession session = new MockHttpSession();
    loginTom(session);
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/IDOR/login")
                .session(session)
                .param("username", "bill")
                .param("password", "buffalo"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted").value(false));
    mockMvc
        .perform(MockMvcRequestBuilders.get("/IDOR/profile").session(session))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void publicTomCredentialsDoNotAuthenticateAnotherAccount() throws Exception {
    MockHttpSession session = new MockHttpSession();
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/IDOR/login")
                .session(session)
                .param("username", "tom")
                .param("password", "cat"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted").value(false));
    mockMvc
        .perform(MockMvcRequestBuilders.get("/IDOR/profile").session(session))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void onlyRealWebGoatAdminCanAccessAnotherProfile() {
    LessonSession session = authenticatedLessonSession();

    assertThatThrownBy(() -> IDORAccessPolicy.requireProfileAccess(session, "2342388"))
        .isInstanceOf(ResponseStatusException.class)
        .satisfies(
            error ->
                assertThat(((ResponseStatusException) error).getStatusCode())
                    .isEqualTo(HttpStatus.FORBIDDEN));

    Authentication previous = SecurityContextHolder.getContext().getAuthentication();
    WebGoatUser admin = new WebGoatUser("test", "password", WebGoatUser.ROLE_ADMIN);
    SecurityContextHolder.getContext()
        .setAuthentication(
            UsernamePasswordAuthenticationToken.authenticated(
                admin, admin.getPassword(), admin.getAuthorities()));
    try {
      assertThatCode(() -> IDORAccessPolicy.requireProfileAccess(session, "2342388"))
          .doesNotThrowAnyException();
    } finally {
      SecurityContextHolder.getContext().setAuthentication(previous);
    }
  }

  @Test
  void profileUpdateNeverCopiesPrivilegedAttributes() {
    LessonSession session = authenticatedLessonSession();
    UserProfile submitted = new UserProfile();
    submitted.setUserId(IDORAccessPolicy.TOM_ID);
    submitted.setName("Attacker");
    submitted.setColor("blue");
    submitted.setRole(1);
    submitted.setAdmin(true);

    new IDOREditOtherProfile(session).completed(IDORAccessPolicy.TOM_ID, submitted);

    UserProfile saved = IDORAccessPolicy.getProfile(session, IDORAccessPolicy.TOM_ID);
    assertThat(saved.getName()).isEqualTo("Tom Cat");
    assertThat(saved.getColor()).isEqualTo("blue");
    assertThat(saved.getRole()).isEqualTo(3);
    assertThat(saved.isAdmin()).isFalse();
  }

  @Test
  void lessonAuthenticationIsBoundToTheWebGoatAccount() {
    LessonSession session = authenticatedLessonSession();
    session.setValue("idor-webgoat-user", "another-user");

    assertThatThrownBy(() -> IDORAccessPolicy.requireLessonUserId(session))
        .isInstanceOf(ResponseStatusException.class)
        .satisfies(
            error ->
                assertThat(((ResponseStatusException) error).getStatusCode())
                    .isEqualTo(HttpStatus.UNAUTHORIZED));
  }

  private LessonSession authenticatedLessonSession() {
    LessonSession session = new LessonSession();
    session.setValue("idor-webgoat-user", "test");
    session.setValue("idor-authenticated-as", "tom");
    session.setValue("idor-authenticated-user-id", IDORAccessPolicy.TOM_ID);
    return session;
  }

  private void loginTom(MockHttpSession session) throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/IDOR/login")
                .session(session)
                .param("username", "test")
                .param("password", "password"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted").value(true));
  }
}
