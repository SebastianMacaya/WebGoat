/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.hijacksession.cas;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedList;
import java.util.Queue;
import java.util.function.Supplier;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Component;
import org.springframework.web.context.annotation.ApplicationScope;

/**
 * @author Angel Olle Blazquez
 */

@ApplicationScope
@Component
public class HijackSessionAuthenticationProvider implements AuthenticationProvider<Authentication> {

  private final Queue<String> sessions = new LinkedList<>();
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();
  protected static final int MAX_SESSIONS = 50;

  private static final Supplier<String> GENERATE_SESSION_ID =
      () -> {
        byte[] bytes = new byte[32];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
      };
  public static final Supplier<Authentication> AUTHENTICATION_SUPPLIER =
      () -> Authentication.builder().id(GENERATE_SESSION_ID.get()).build();

  @Override
  public synchronized Authentication authenticate(Authentication authentication) {
    if (authentication == null) {
      return AUTHENTICATION_SUPPLIER.get();
    }

    if (StringUtils.isNotEmpty(authentication.getId())
        && sessions.contains(authentication.getId())) {
      authentication.setAuthenticated(true);
      return authentication;
    }

    if (StringUtils.isEmpty(authentication.getId())) {
      authentication.setId(GENERATE_SESSION_ID.get());
    }

    return authentication;
  }

  protected synchronized boolean addSession(String sessionId) {
    if (sessions.size() >= MAX_SESSIONS) {
      sessions.remove();
    }
    return sessions.add(sessionId);
  }

  protected synchronized int getSessionsSize() {
    return sessions.size();
  }
}
