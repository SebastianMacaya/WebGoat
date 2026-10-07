/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.hijacksession.cas;

import java.security.SecureRandom;
import java.util.LinkedList;
import java.util.Queue;
import java.util.concurrent.ThreadLocalRandom;
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
      () ->
          Long.toString(SECURE_RANDOM.nextLong() & Long.MAX_VALUE)
              + "-"
              + Long.toString(SECURE_RANDOM.nextLong() & Long.MAX_VALUE);
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

    authorizedUserAutoLogin();

    return authentication;
  }

  protected void authorizedUserAutoLogin() {
    if (ThreadLocalRandom.current().nextDouble() >= 0.75) {
      addSession(GENERATE_SESSION_ID.get());
    }
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
