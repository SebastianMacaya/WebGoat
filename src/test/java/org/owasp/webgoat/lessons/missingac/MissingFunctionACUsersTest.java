/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.UUID;
import org.assertj.core.api.Assertions;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.WithWebGoatUser;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.owasp.webgoat.container.users.WebGoatUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class MissingFunctionACUsersTest extends LessonTest {

  @Autowired private MissingAccessControlUserRepository userRepository;

  @BeforeEach
  void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  @Test
  void ordinaryUserCannotListUsers() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/access-control/users")
                .header("Content-type", "application/json"))
        .andExpect(status().isForbidden());
    mockMvc
        .perform(MockMvcRequestBuilders.get("/access-control/users"))
        .andExpect(status().isForbidden());
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/access-control/users-admin-fix")
                .header("Content-type", "application/json"))
        .andExpect(status().isForbidden());
  }

  @Test
  @WithWebGoatUser(role = WebGoatUser.ROLE_ADMIN)
  void administratorCanListUsers() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/access-control/users")
                .header("Content-type", "application/json"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].username", CoreMatchers.is("Tom")))
        .andExpect(
            jsonPath(
                "$[0].userHash", CoreMatchers.is("Mydnhcy00j2b0m6SjmPz6PUxF9WIeO7tzm665GiZWCo=")))
        .andExpect(jsonPath("$[0].admin", CoreMatchers.is(false)));
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/access-control/users-admin-fix")
                .header("Content-type", "application/json"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].username", CoreMatchers.is("Tom")));
  }

  @Test
  void ordinaryUserCannotGrantItselfAdmin() throws Exception {
    String username = "unauthorized-" + UUID.randomUUID().toString().substring(0, 8);
    String user =
        """
        {"username":"%s","password":"newUser12","admin": "true"}
        """
            .formatted(username);
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/access-control/users")
                .header("Content-type", "application/json")
                .content(user))
        .andExpect(status().isForbidden());
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/access-control/users-admin-fix")
                .header("Content-type", "application/json")
                .content(user))
        .andExpect(status().isForbidden());
    Assertions.assertThat(userRepository.findByUsername(username)).isNull();
  }

  @Test
  @WithWebGoatUser(role = WebGoatUser.ROLE_ADMIN)
  void administratorCanAddUser() throws Exception {
    String username = "admin-created-" + UUID.randomUUID().toString().substring(0, 8);
    String user =
        """
        {"username":"%s","password":"newUser12","admin": "false"}
        """
            .formatted(username);
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/access-control/users-admin-fix")
                .header("Content-type", "application/json")
                .content(user))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.username", is(username)));
    Assertions.assertThat(userRepository.findByUsername(username)).isNotNull();
  }
}
