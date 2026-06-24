# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener
from java.io import PrintWriter
import json
import re
import time
import base64

class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        self._stdout    = PrintWriter(callbacks.getStdout(), True)
        self._stderr    = PrintWriter(callbacks.getStderr(), True)

        callbacks.setExtensionName("SSO JSESSIONID JWT Auto Refresher + License Manager")
        callbacks.registerHttpListener(self)

        # =====================================================
        # CONFIGURE THESE VALUES ONLY
        # =====================================================

        # Full SSO URL with query params - paste exact URL here
        self.sso_url = "https://sso.com/sgconnect/oauth2/authorize?scope=openid%20profile&response_type=code&redirect_uri=https://host.com/explorer-wa/&nonce=MTc4MDk4MTM1MTY50A%3D%3D&client_id=XXXXXXXXXXXXXXXX"

        # SSO cookies - update these daily
        self.sso_cookies = "SGX_tid=XXXXXXXXXXXXXXXXXXXXXXXX; sgx-11=XXXXXXXXXXXXXXXX; OAUTH_REQUEST_ATTRIBUTES=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX; SGX_PRD_authN_sticky_id=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX; amlbcookie=01; 12=XXXXXXXXXXXX"

        # Token endpoint
        self.token_url = "https://host.com/explore-wa/token"

        # =====================================================
        # LOGOUT / LICENSE MANAGEMENT CONFIG
        # =====================================================

        # Logout endpoint (from Burp capture)
        self.logout_url = "https://api.main.com/tb-server/api/v1.0.0/browser/logoffRequests"

        # The userId you are CURRENTLY scanning as.
        # This user will NEVER be logged out by the auto-license-free logic,
        # so your active scan session is never killed.
        self.current_scan_user = "BAS1009929044"

        # List of userIds whose stale sessions can be freed.
        # Replace these with IDs of zombie/previous sessions that are
        # occupying licenses. The extension cycles through this list
        # each time it needs to free a license.
        #
        # CRITICAL: Do NOT put self.current_scan_user in this list,
        #           otherwise you will kill your own scan session.
        self.logout_target_userids = [
            # "BAS1009929045",
            # "BAS1009929046",
        ]

        # Headers required by the logout endpoint (copy from Burp capture)
        self.logout_default_company  = "BE0010001"
        self.logout_default_username = "SHOU1009929044"
        self.logout_noos_1           = "213541985925578.03:7"
        self.logout_noos_2           = "CSAM-CHECKER-BRU"
        self.logout_referer          = "https://main.com/"
        self.logout_origin           = "https://main.com"

        # Response body markers that indicate all licenses are occupied.
        # Add the EXACT strings you see in the real "license full" response.
        # Matching is case-insensitive.
        self.license_exhausted_markers = [
            "license",
            "all licenses",
            "occupied",
            "maximum concurrent",
            "no license available",
            "session limit",
            "concurrent session",
        ]

        # Cooldown (seconds) between logout attempts to avoid hammering
        # the endpoint when many requests fail at once.
        self.logout_cooldown_seconds = 15
        self._last_logout_time = 0

        # =====================================================
        # SESSION CACHING CONFIG
        # =====================================================
        # JSESSIONID is believed to live ~30 min (unverified).
        # We cache it for 15 min to be safe — if the real lifetime is
        # shorter, the 302 fallback inside _fetch_jwt will catch it.
        # If you later confirm the real lifetime, set this to (lifetime - 5 min).
        self.JSESSIONID_TTL_SECONDS = 900  # 15 minutes

        # JWT lives ~10 min. We check its real 'exp' claim at runtime
        # (see _is_jwt_expired), so no separate TTL is needed. The JWT
        # is cached in self._jwt_token and reused for BOTH scan retries
        # AND logout calls until it is within 30s of expiry.
        self.JWT_EXPIRY_BUFFER_SECONDS = 30

        # =====================================================

        self._jsessionid = None
        self._jsessionid_fetched_at = 0
        self._jwt_token  = None

        self._stdout.println("SSO JSESSIONID JWT Refresher + License Manager loaded successfully")
        self._stdout.println("Current scan user (protected from logout): " + self.current_scan_user)
        self._stdout.println("Logout target userIds configured: " + str(len(self.logout_target_userids)))

    # ----------------------------------------------------------
    # MAIN HTTP LISTENER ENTRY POINT
    # ----------------------------------------------------------
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        try:
            if messageIsRequest:
                return

            response_bytes = messageInfo.getResponse()
            if response_bytes is None:
                return

            resp_info   = self._helpers.analyzeResponse(response_bytes)
            body_offset = resp_info.getBodyOffset()
            resp_body   = self._helpers.bytesToString(response_bytes[body_offset:])

            # ---------------------------------------------------
            # PATH A: JWT expired -> refresh and retry
            # ---------------------------------------------------
            if "Jwt token Expired!" in resp_body:
                self._stdout.println("JWT expired detected in response - starting refresh flow")

                if not self._refresh_full_jwt_chain():
                    self._stderr.println("FAILED - could not refresh JWT chain")
                    return

                self._stdout.println("JWT refresh complete - retrying original request")
                self._retry_with_new_jwt(messageInfo)
                return

            # ---------------------------------------------------
            # PATH B: License exhausted -> logout a stale user, then retry
            # ---------------------------------------------------
            if self._is_license_exhausted(resp_body, resp_info.getStatusCode()):
                self._stdout.println("License exhaustion detected in response - attempting logout to free a license")
                freed = self._free_one_license()
                if freed:
                    self._stdout.println("License freed - retrying original request")
                    # JWT should still be valid here (it was valid enough to
                    # reach the app and get a "license full" response).
                    # If it has also expired, the retry will trigger Path A.
                    self._retry_original(messageInfo)
                else:
                    self._stderr.println("Could not free a license - manual intervention required")
                return

        except Exception as e:
            self._stderr.println("processHttpMessage error: " + str(e))

    # ===========================================================
    # LICENSE MANAGEMENT
    # ===========================================================

    def _is_license_exhausted(self, body, status_code):
        """Detect whether the response indicates all licenses are occupied.
        Uses both status code (403/429/503) and body keyword matching."""
        try:
            # Strong signal: specific status codes that usually mean
            # "too many sessions" or "forbidden due to licensing"
            if status_code in [429, 503]:
                return True

            body_lower = body.lower()
            for marker in self.license_exhausted_markers:
                if marker.lower() in body_lower:
                    # Avoid false positive: make sure it's not just the word
                    # "license" appearing in a normal response. Require at
                    # least one of the stronger markers OR a 4xx status.
                    if marker.lower() in ["license"]:
                        # Only count "license" if paired with a 4xx status
                        # or another stronger marker
                        if status_code >= 400:
                            return True
                        continue
                    return True
            return False
        except Exception:
            return False

    def _free_one_license(self):
        """Try to logout one stale user to free a license.
        Skips the current scan user. Respects a cooldown."""
        try:
            now = time.time()
            if now - self._last_logout_time < self.logout_cooldown_seconds:
                self._stdout.println("Logout cooldown active - skipping (last logout " + str(int(now - self._last_logout_time)) + "s ago)")
                return False

            if not self.logout_target_userids:
                self._stderr.println("No logout target userIds configured - cannot free license automatically")
                self._stderr.println("Add userIds to self.logout_target_userids in the config section")
                return False

            for uid in self.logout_target_userids:
                if uid == self.current_scan_user:
                    self._stdout.println("Skipping logout for current scan user (protected): " + uid)
                    continue
                if self._perform_logout(uid):
                    self._last_logout_time = time.time()
                    self._stdout.println("License freed by logging out user: " + uid)
                    return True

            self._stderr.println("No logout target succeeded - all attempts failed")
            return False

        except Exception as e:
            self._stderr.println("_free_one_license error: " + str(e))
            return False

    def _perform_logout(self, user_id):
        """Send POST to /logoffRequests to terminate the given user's session.

        JWT caching note: the SAME cached JWT (self._jwt_token) is reused
        for both scan retries and logout calls. We do NOT fetch a separate
        token for logout. The logout endpoint authenticates the CALLER via
        the JWT; the session to terminate is identified by user_id in the
        body, not by the JWT. So any currently-valid JWT works.

        Returns True on success (2xx), False otherwise."""
        try:
            # ---- Ensure we have a valid, non-expired JWT (cached) ----
            if not self._jwt_token or self._is_jwt_expired(self._jwt_token):
                self._stdout.println("JWT missing or near-expiry - refreshing before logout (caches new JWT for future logouts)")
                if not self._refresh_full_jwt_chain():
                    self._stderr.println("Could not refresh JWT before logout")
                    return False
            else:
                self._stdout.println("Reusing cached JWT for logout")

            # ---- Build and send the logout request ----
            success = self._send_logout_request(user_id, self._jwt_token)
            if success:
                return True

            # ---- If logout returned 401/403, JWT may have expired
            #      between the check and the request. Refresh and retry once.
            self._stderr.println("Logout failed - refreshing JWT and retrying once")
            if self._refresh_full_jwt_chain():
                return self._send_logout_request(user_id, self._jwt_token)

            return False

        except Exception as e:
            self._stderr.println("_perform_logout error: " + str(e))
            return False

    def _send_logout_request(self, user_id, jwt_token):
        """Builds and sends the actual POST to /logoffRequests."""
        try:
            host = self._host(self.logout_url)
            path = self._extract_path(self.logout_url)

            body_str = json.dumps({"body": {"userId": user_id}})

            # NOTE: The original Burp capture shows TWO "Noos:" headers with
            # different values. This is unusual but we replicate it exactly
            # to match what the server expects.
            headers = [
                "POST " + path + " HTTP/1.1",
                "Host: " + host,
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:152.0) Gecko/20100101 Firefox/152.0",
                "Accept: application/json, text/plain, */*",
                "Accept-Language: en-US,en;q=0.9",
                "Accept-Encoding: gzip, deflate, br",
                "Referer: " + self.logout_referer,
                "Authorization: Bearer " + jwt_token,
                "Noos: " + self.logout_noos_1,
                "Defaultcompany: " + self.logout_default_company,
                "Defaultusername: " + self.logout_default_username,
                "Noos: " + self.logout_noos_2,
                "Content-Type: application/json",
                "Origin: " + self.logout_origin,
                "Sec-Fetch-Dest: empty",
                "Sec-Fetch-Mode: cors",
                "Sec-Fetch-Site: same-site",
                "Connection: close"
            ]

            response_bytes = self._make_request(self.logout_url, headers, body_str)
            if response_bytes is None:
                self._stderr.println("Logout request returned no response")
                return False

            resp_info    = self._helpers.analyzeResponse(response_bytes)
            status       = resp_info.getStatusCode()
            body_offset  = resp_info.getBodyOffset()
            resp_body    = self._helpers.bytesToString(response_bytes[body_offset:])

            self._stdout.println("Logout response status: " + str(status) + " body: " + resp_body[:200])

            if status in [401, 403]:
                self._stderr.println("Logout auth rejected (status " + str(status) + ")")
                return False

            return 200 <= status < 300

        except Exception as e:
            self._stderr.println("_send_logout_request error: " + str(e))
            return False

    def _is_jwt_expired(self, jwt_token):
        """Decode the JWT payload (without verifying signature) and check
        the 'exp' claim. Returns True if expired or within the safety
        buffer of expiry. This is what enables JWT caching — the same
        token is reused for both scan retries and logout calls until
        it is about to expire, then a single refresh serves both uses."""
        try:
            parts = jwt_token.split(".")
            if len(parts) != 3:
                return False
            payload = parts[1]
            # Fix base64 padding
            payload += "=" * (4 - len(payload) % 4)
            decoded = base64.urlsafe_b64decode(payload)
            data = json.loads(decoded)
            exp = data.get("exp")
            if not exp:
                return False
            # Refresh before actual expiry to avoid mid-request expiry
            return time.time() >= (exp - self.JWT_EXPIRY_BUFFER_SECONDS)
        except Exception:
            # If we can't decode, assume valid and let the server reject it
            return False

    def _refresh_full_jwt_chain(self):
        """Refresh the JWT. Reuses cached JSESSIONID if still within TTL,
        otherwise runs the full SSO -> Location -> JSESSIONID chain first.
        The JWT itself is always re-fetched because this function is only
        called when the JWT is known to be expired or missing.
        Returns True on success."""
        try:
            # ---- Step 1+2: JSESSIONID (cached if still valid) ----
            if self._is_jsessionid_valid():
                age = int(time.time() - self._jsessionid_fetched_at)
                self._stdout.println("Reusing cached JSESSIONID (age " + str(age) + "s, TTL " + str(self.JSESSIONID_TTL_SECONDS) + "s)")
            else:
                location_url = self._get_sso_location()
                if not location_url:
                    self._stderr.println("FAILED at Step 1 - could not get Location URL from SSO")
                    return False
                self._stdout.println("Step 1 done - Location URL obtained")

                jsessionid = self._fetch_jsessionid(location_url)
                if not jsessionid:
                    self._stderr.println("FAILED at Step 2 - could not extract JSESSIONID")
                    return False
                self._jsessionid = jsessionid
                self._jsessionid_fetched_at = time.time()
                self._stdout.println("Step 2 done - JSESSIONID obtained (fresh)")

            # ---- Step 3: JWT (always fetched — caller knows it's expired) ----
            jwt_token = self._fetch_jwt()
            if not jwt_token:
                self._stderr.println("FAILED at Step 3 - could not obtain JWT token")
                return False
            self._jwt_token = jwt_token
            self._stdout.println("Step 3 done - JWT token obtained")
            return True

        except Exception as e:
            self._stderr.println("_refresh_full_jwt_chain error: " + str(e))
            return False

    def _is_jsessionid_valid(self):
        """Returns True if we have a cached JSESSIONID that is still within
        its TTL. Note: this is a SOFT check. If the real session expired
        earlier than our TTL assumes, the token endpoint will return 302
        and _fetch_jwt will reactively re-fetch the JSESSIONID."""
        if not self._jsessionid:
            return False
        age = time.time() - self._jsessionid_fetched_at
        return age < self.JSESSIONID_TTL_SECONDS

    # ===========================================================
    # SSO / JWT FLOW (original steps, unchanged logic)
    # ===========================================================

    # ----------------------------------------------------------
    # STEP 1 - GET SSO URL - extract Location header
    # ----------------------------------------------------------
    def _get_sso_location(self):
        try:
            host = self._host(self.sso_url)
            path = self._extract_path(self.sso_url)

            self._stdout.println("SSO path being sent: " + path[:100])

            headers = [
                "GET " + path + " HTTP/1.1",
                "Host: " + host,
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:151.0) Gecko/20100101 Firefox/151.0",
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language: en-US,en;q=0.9",
                "Accept-Encoding: gzip, deflate, br",
                "Referer: https://sso.com/",
                "Upgrade-Insecure-Requests: 1",
                "Sec-Fetch-Dest: document",
                "Sec-Fetch-Mode: navigate",
                "Sec-Fetch-Site: same-origin",
                "Sec-Fetch-User: ?1",
                "Priority: u=0, i",
                "Te: trailers",
                "Cookie: " + self.sso_cookies,
                "Connection: close"
            ]

            response_bytes = self._make_request(self.sso_url, headers, None)
            if response_bytes is None:
                self._stderr.println("SSO request returned no response")
                return None

            resp_info    = self._helpers.analyzeResponse(response_bytes)
            status       = resp_info.getStatusCode()
            resp_headers = resp_info.getHeaders()

            self._stdout.println("SSO response status: " + str(status))

            if status in [301, 302, 303, 307, 308]:
                for hdr in resp_headers:
                    if hdr.lower().startswith("location:"):
                        location = hdr.split(":", 1)[1].strip()
                        self._stdout.println("Location URL found: " + location[:80])
                        return location

            self._stderr.println("No Location header found. Status: " + str(status))
            return None

        except Exception as e:
            self._stderr.println("_get_sso_location error: " + str(e))
            return None

    # ----------------------------------------------------------
    # STEP 2 - Follow Location URL - extract JSESSIONID
    # ----------------------------------------------------------
    def _fetch_jsessionid(self, location_url):
        try:
            if location_url.startswith("/"):
                location_url = self._scheme(self.sso_url) + "://" + self._host(self.sso_url) + location_url

            host = self._host(location_url)
            path = self._extract_path(location_url)

            self._stdout.println("Following Location path: " + path[:100])

            headers = [
                "GET " + path + " HTTP/1.1",
                "Host: " + host,
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:151.0) Gecko/20100101 Firefox/151.0",
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language: en-US,en;q=0.9",
                "Accept-Encoding: gzip, deflate, br",
                "Referer: https://sso.com/",
                "Sec-Fetch-Dest: document",
                "Sec-Fetch-Mode: navigate",
                "Sec-Fetch-Site: cross-site",
                "Cookie: " + self.sso_cookies,
                "Connection: close"
            ]

            response_bytes = self._make_request(location_url, headers, None)
            if response_bytes is None:
                self._stderr.println("Location URL request returned no response")
                return None

            resp_info    = self._helpers.analyzeResponse(response_bytes)
            status       = resp_info.getStatusCode()
            resp_headers = resp_info.getHeaders()

            self._stdout.println("Location URL response status: " + str(status))

            if status in [301, 302, 303, 307, 308]:
                self._stderr.println("302 on Location URL - SSO cookies may be expired. Please update sso_cookies manually.")
                return None

            for hdr in resp_headers:
                if "set-cookie" in hdr.lower() and "jsessionid" in hdr.lower():
                    match = re.search(r'JSESSIONID=([^;,\s]+)', hdr, re.IGNORECASE)
                    if match:
                        self._stdout.println("JSESSIONID extracted successfully")
                        return match.group(1)

            self._stderr.println("JSESSIONID not found in Set-Cookie header")
            return None

        except Exception as e:
            self._stderr.println("_fetch_jsessionid error: " + str(e))
            return None

    # ----------------------------------------------------------
    # STEP 3 - GET token endpoint with JSESSIONID - extract JWT
    # ----------------------------------------------------------
    def _fetch_jwt(self):
        try:
            host = self._host(self.token_url)
            path = self._extract_path(self.token_url)

            headers = [
                "GET " + path + " HTTP/1.1",
                "Host: " + host,
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:151.0) Gecko/20100101 Firefox/151.0",
                "Accept: application/json, text/plain, */*",
                "Accept-Language: en-US,en;q=0.9",
                "Cookie: JSESSIONID=" + self._jsessionid,
                "Connection: close"
            ]

            response_bytes = self._make_request(self.token_url, headers, None)
            if response_bytes is None:
                self._stderr.println("Token endpoint returned no response")
                return None

            resp_info   = self._helpers.analyzeResponse(response_bytes)
            status      = resp_info.getStatusCode()
            body_offset = resp_info.getBodyOffset()
            resp_body   = self._helpers.bytesToString(response_bytes[body_offset:])

            self._stdout.println("Token endpoint status: " + str(status))

            if status in [301, 302, 303, 307, 308]:
                self._stderr.println("302 on token endpoint - JSESSIONID expired - restarting from SSO")
                location_url = self._get_sso_location()
                if not location_url:
                    return None
                jsessionid = self._fetch_jsessionid(location_url)
                if not jsessionid:
                    return None
                self._jsessionid = jsessionid
                return self._fetch_jwt()

            try:
                data  = json.loads(resp_body)
                token = data.get("token")
                if token:
                    self._stdout.println("JWT token extracted from response")
                    return token
                else:
                    self._stderr.println("Key 'token' not found in response: " + resp_body[:200])
                    return None
            except Exception as e:
                self._stderr.println("JSON parse error: " + str(e) + " Body: " + resp_body[:200])
                return None

        except Exception as e:
            self._stderr.println("_fetch_jwt error: " + str(e))
            return None

    # ===========================================================
    # RETRY HELPERS
    # ===========================================================

    # ----------------------------------------------------------
    # STEP 4 - Retry original request with new JWT injected
    # ----------------------------------------------------------
    def _retry_with_new_jwt(self, messageInfo):
        try:
            original_request = messageInfo.getRequest()
            req_info         = self._helpers.analyzeRequest(original_request)
            headers          = list(req_info.getHeaders())
            body             = original_request[req_info.getBodyOffset():]

            new_headers = []
            replaced    = False

            for hdr in headers:
                if hdr.lower().startswith("authorization:"):
                    new_headers.append("Authorization: Bearer " + self._jwt_token)
                    replaced = True
                    self._stdout.println("Authorization header replaced with new JWT")
                else:
                    new_headers.append(hdr)

            if not replaced:
                new_headers.append("Authorization: Bearer " + self._jwt_token)
                self._stdout.println("Authorization header added with new JWT")

            new_request  = self._helpers.buildHttpMessage(new_headers, body)
            http_service = messageInfo.getHttpService()
            new_response = self._callbacks.makeHttpRequest(http_service, new_request)

            messageInfo.setRequest(new_request)
            messageInfo.setResponse(new_response.getResponse())

            self._stdout.println("Request retried successfully with new JWT")

        except Exception as e:
            self._stderr.println("_retry_with_new_jwt error: " + str(e))

    # ----------------------------------------------------------
    # STEP 5 - Retry original request AS-IS (used after logout
    #          frees a license; JWT is assumed still valid)
    # ----------------------------------------------------------
    def _retry_original(self, messageInfo):
        try:
            original_request = messageInfo.getRequest()
            http_service     = messageInfo.getHttpService()
            new_response     = self._callbacks.makeHttpRequest(http_service, original_request)
            messageInfo.setResponse(new_response.getResponse())
            self._stdout.println("Original request retried after license freed")
        except Exception as e:
            self._stderr.println("_retry_original error: " + str(e))

    # ===========================================================
    # UTILITY HELPERS
    # ===========================================================

    def _make_request(self, url, headers, body):
        try:
            use_https  = url.lower().startswith("https")
            host       = self._host(url)
            port       = 443 if use_https else 80
            http_svc   = self._helpers.buildHttpService(host, port, use_https)
            body_bytes = self._helpers.stringToBytes(body) if body else []
            req_bytes  = self._helpers.buildHttpMessage(headers, body_bytes)
            response   = self._callbacks.makeHttpRequest(http_svc, req_bytes)
            return response.getResponse() if response else None
        except Exception as e:
            self._stderr.println("_make_request error: " + str(e))
            return None

    def _host(self, url):
        no_scheme = re.sub(r'^https?://', '', url)
        return no_scheme.split("/")[0].split("?")[0]

    def _scheme(self, url):
        return "https" if url.lower().startswith("https") else "http"

    def _extract_path(self, url):
        match = re.match(r'^https?://[^/]+(.*)', url)
        if match:
            path = match.group(1)
            return path if path else "/"
        return "/"
