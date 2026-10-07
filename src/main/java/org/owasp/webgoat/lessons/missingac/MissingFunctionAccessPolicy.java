/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import org.owasp.webgoat.container.users.WebGoatUser;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.server.ResponseStatusException;

final class MissingFunctionAccessPolicy {

  private MissingFunctionAccessPolicy() {}

  static void requireAdmin() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication == null
        || !authentication.isAuthenticated()
        || authentication.getAuthorities().stream()
            .noneMatch(authority -> WebGoatUser.ROLE_ADMIN.equals(authority.getAuthority()))) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN);
    }
  }
}
