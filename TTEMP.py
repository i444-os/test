# -*- coding: utf-8 -*-
"""
OAuth2 Auto-Token Manager v2 - Burp Suite Extension
Jython 2.7.4 Standalone Compatible

3-Step OAuth2 Flow:
  Step 1: GET /oauth2/authorize (SSO cookies) -> 302 redirect with code
  Step 2: GET /app-base-path/?code=... -> 200, Set-Cookie: JSESSIONID + INGRESSCOOKIE
  Step 3: GET /app-base-path/token (JSESSIONID) -> JSON with JWT

Features:
  - Caches JWT until expiry (exp claim) or 401; auto-refreshes lazily
  - Injects Authorization: Bearer <jwt> into all requests targeting main domain
  - Replaces JSESSIONID + INGRESSCOOKIE in Cookie headers on main domain
  - Two-level header removal: "All Requests" (global) + "Main Domain Only"
  - Configurable tool scope checkboxes (Proxy, Repeater, Intruder, Scanner, etc.)
  - Start / Stop / Force Refresh controls
  - 30-second cooldown after failed refresh
  - Thread-safe token cache with lazy refresh
  - Memory-bounded log (auto-trims at 50KB)
  - Swing UI tab (Active Scan++ / Gitleaks style)
"""

from burp import IBurpExtender, ITab, IHttpListener
from javax.swing import (
    JPanel, JButton, JTextField, JLabel, JCheckBox,
    JTextArea, JScrollPane, BorderFactory, BoxLayout, Box,
    SwingUtilities, JComboBox
)
from javax.swing.border import TitledBorder, EmptyBorder, EtchedBorder, MatteBorder
from java.awt import (
    GridBagLayout, GridBagConstraints, Insets, FlowLayout,
    BorderLayout, Dimension, Font, Color, GridLayout
)
from java.net import URLEncoder, URL
import json
import base64
import time
import threading
import re


# ---------------------------------------------------------------------------
# Runnable helpers for Swing EDT safety (Jython 2.7 duck-typing approach)
# ---------------------------------------------------------------------------

class _RunnableUpdateStatus(object):
    def __init__(self, ext, text):
        self._ext = ext
        self._text = text
    def run(self):
        self._ext._lbl_status.setText("Status: %s" % self._text)


class _RunnableUpdateTokenInfo(object):
    def __init__(self, ext, text):
        self._ext = ext
        self._text = text
    def run(self):
        self._ext._lbl_token_info.setText(self._text)


class _RunnableAppendLog(object):
    def __init__(self, ext, line):
        self._ext = ext
        self._line = line
    def run(self):
        current = self._ext._txt_log.getText()
        if len(current) > 50000:
            current = current[-25000:]
        self._ext._txt_log.setText(current + self._line + "\n")
        doc = self._ext._txt_log.getDocument()
        self._ext._txt_log.setCaretPosition(doc.getLength())


# ---------------------------------------------------------------------------
# Main Extension Class
# ---------------------------------------------------------------------------

class BurpExtender(IBurpExtender, ITab, IHttpListener):

    TOOL_PROXY     = 4
    TOOL_SCANNER   = 16
    TOOL_INTRUDER  = 32
    TOOL_REPEATER  = 64
    TOOL_SEQUENCER = 128
    TOOL_EXTENDER  = 256
    TOOL_TARGET    = 8

    REFRESH_COOLDOWN = 30
    TOKEN_BUFFER     = 30

    # ------------------------------------------------------------------
    # IBurpExtender
    # ------------------------------------------------------------------

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()

        self._running              = False
        self._token_cache          = None
        self._token_expiry         = 0
        self._jsessionid           = None
        self._ingresscookie        = None
        self._last_refresh_attempt = 0
        self._refresh_count        = 0
        self._token_lock           = threading.Lock()
        self._refreshing           = False

        callbacks.setExtensionName("OAuth2 Auto-Token Manager")
        self._build_ui()
        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)

        self._log("OAuth2 Auto-Token Manager v2 loaded.")
        self._log("Configure settings and click 'Start' to begin.")

    # ------------------------------------------------------------------
    # ITab
    # ------------------------------------------------------------------

    def getTabCaption(self):
        return "OAuth2 Token"

    def getUiComponent(self):
        return self._main_panel

    # ------------------------------------------------------------------
    # IHttpListener
    # ------------------------------------------------------------------

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not self._running:
            return
        try:
            if not self._should_process(toolFlag):
                return
            if messageIsRequest:
                self._process_request(messageInfo)
            else:
                self._process_response(messageInfo)
        except Exception as e:
            self._log("processHttpMessage error: %s" % str(e))

    # ------------------------------------------------------------------
    # Request / Response processing
    # ------------------------------------------------------------------

    def _should_process(self, toolFlag):
        mapping = {
            self.TOOL_PROXY:     self._chk_proxy,
            self.TOOL_REPEATER:  self._chk_repeater,
            self.TOOL_INTRUDER:  self._chk_intruder,
            self.TOOL_SCANNER:   self._chk_scanner,
            self.TOOL_SEQUENCER: self._chk_sequencer,
            self.TOOL_EXTENDER:  self._chk_extensions,
            self.TOOL_TARGET:    self._chk_target,
        }
        chk = mapping.get(toolFlag)
        return chk is not None and chk.isSelected()

    def _process_request(self, messageInfo):
        """
        Two-phase request modification:
          Phase 1 (ALL domains in tool scope): Remove global headers
          Phase 2 (main domain only): Remove domain-specific headers,
                  replace JSESSIONID/INGRESSCOOKIE in Cookie header,
                  add Authorization: Bearer <jwt>
        """
        http_service = messageInfo.getHttpService()
        if http_service is None:
            return

        request = messageInfo.getRequest()
        if request is None:
            return

        request_info = self._helpers.analyzeRequest(messageInfo)
        headers = list(request_info.getHeaders())
        body = request[request_info.getBodyOffset():]

        host = http_service.getHost()
        main_domain = self._txt_main_domain.getText().strip()
        is_main = (main_domain != "" and host == main_domain)

        modified = False

        # --- Phase 1: Global header removal (ALL domains) ---
        global_remove = self._get_global_headers_to_remove()
        if global_remove:
            headers, changed = self._strip_headers(headers, global_remove)
            if changed:
                modified = True

        # --- Phase 2: Main-domain-only modifications ---
        if is_main:
            # 2a. Remove domain-specific headers
            domain_remove = self._get_domain_headers_to_remove()
            if domain_remove:
                headers, changed = self._strip_headers(headers, domain_remove)
                if changed:
                    modified = True

            # 2b. Replace JSESSIONID in Cookie header
            if self._jsessionid:
                headers, changed = self._replace_cookie_value(
                    headers, "JSESSIONID", self._jsessionid)
                if changed:
                    modified = True

            # 2c. Replace INGRESSCOOKIE in Cookie header
            if self._ingresscookie:
                headers, changed = self._replace_cookie_value(
                    headers, "INGRESSCOOKIE", self._ingresscookie)
                if changed:
                    modified = True

            # 2d. Add / replace Authorization header
            token = self._get_cached_token()
            if token:
                headers, changed = self._set_auth_header(headers, token)
                if changed:
                    modified = True

        if modified:
            new_request = self._helpers.buildHttpMessage(headers, body)
            messageInfo.setRequest(new_request)

    def _process_response(self, messageInfo):
        """Watch for 401 from the protected domain -> invalidate cache."""
        response = messageInfo.getResponse()
        if response is None:
            return

        http_service = messageInfo.getHttpService()
        if http_service is None:
            return

        host = http_service.getHost()
        main_domain = self._txt_main_domain.getText().strip()
        if not main_domain or host != main_domain:
            return

        response_info = self._helpers.analyzeResponse(response)
        if response_info.getStatusCode() == 401:
            self._log("401 detected from %s - invalidating token" % host)
            self._invalidate_token()

    # ------------------------------------------------------------------
    # Token management
    # ------------------------------------------------------------------

    def _get_cached_token(self):
        with self._token_lock:
            if self._token_cache and self._is_token_valid():
                return self._token_cache
            if self._token_cache is None and \
               (time.time() - self._last_refresh_attempt) < self.REFRESH_COOLDOWN:
                return None
            self._do_refresh()
            return self._token_cache

    def _is_token_valid(self):
        if not self._token_cache:
            return False
        return time.time() < (self._token_expiry - self.TOKEN_BUFFER)

    def _invalidate_token(self):
        with self._token_lock:
            self._token_cache  = None
            self._token_expiry = 0
            self._jsessionid   = None
            self._ingresscookie = None
        self._update_token_info("Token: INVALIDATED")

    def _do_refresh(self):
        """Must be called while holding _token_lock."""
        if self._refreshing:
            return
        self._refreshing = True
        self._last_refresh_attempt = time.time()
        try:
            self._edt_status("Refreshing token...")
            token = self._execute_token_flow()
            if token:
                self._token_cache  = token
                self._token_expiry = self._decode_jwt_expiry(token)
                self._refresh_count += 1
                exp_str = time.strftime("%H:%M:%S", time.localtime(self._token_expiry))
                iat = self._decode_jwt_field(token, "iat")
                iat_str = time.strftime("%H:%M:%S", time.localtime(iat)) if iat else "?"
                self._log("Token refreshed (#%d). Issued: %s | Expires: %s" % (
                    self._refresh_count, iat_str, exp_str))
                self._edt_status("Running - Token valid until %s" % exp_str)
                if len(token) > 35:
                    preview = token[:20] + "..." + token[-12:]
                else:
                    preview = token[:15] + "..."
                self._update_token_info("Token: %s" % preview)
            else:
                self._log("Token refresh FAILED. Check config / cookies.")
                self._edt_status("Refresh FAILED - check log")
                self._update_token_info("Token: NONE (refresh failed)")
        except Exception as e:
            self._log("Token refresh exception: %s" % str(e))
            self._edt_status("Refresh ERROR - check log")
        finally:
            self._refreshing = False

    # ------------------------------------------------------------------
    # 3-step OAuth2 flow
    # ------------------------------------------------------------------

    def _execute_token_flow(self):
        sso_domain   = self._txt_sso_domain.getText().strip()
        main_domain  = self._txt_main_domain.getText().strip()
        client_id    = self._txt_client_id.getText().strip()
        redirect_uri = self._txt_redirect_uri.getText().strip()
        scope        = self._txt_scope.getText().strip()
        sso_path     = self._txt_sso_path.getText().strip()
        base_path    = self._txt_base_path.getText().strip()
        sso_cookies  = self._txt_sso_cookies.getText().strip().replace("\n", " ").replace("\r", "")

        if not sso_domain or not main_domain or not client_id or not redirect_uri or not sso_cookies:
            self._log("Missing required config: SSO Domain, Main Domain, Client ID, Redirect URI, and SSO Cookies are all required.")
            return None

        redirect_url = self._step1_authorize(
            sso_domain, sso_path, client_id, redirect_uri, scope, sso_cookies)
        if not redirect_url:
            return None

        jsessionid, ingresscookie = self._step2_exchange_code(redirect_url, main_domain)
        if not jsessionid:
            return None
        self._jsessionid = jsessionid
        if ingresscookie:
            self._ingresscookie = ingresscookie

        token, ingresscookie2 = self._step3_get_token(main_domain, base_path, jsessionid)
        if not token:
            return None
        # Step 3 may return an updated INGRESSCOOKIE
        if ingresscookie2:
            self._ingresscookie = ingresscookie2

        self._log("Cached: JSESSIONID=%s... | INGRESSCOOKIE=%s" % (
            jsessionid[:12] if jsessionid else "None",
            ingresscookie2[:12] if ingresscookie2 else (ingresscookie[:12] if ingresscookie else "None")))
        return token

    # -- Step 1 ---------------------------------------------------------

    def _step1_authorize(self, sso_domain, sso_path, client_id, redirect_uri, scope, sso_cookies):
        try:
            nonce_raw = str(int(time.time() * 1000))
            nonce     = base64.b64encode(nonce_raw).replace("\n", "").replace("\r", "")

            scope_enc    = URLEncoder.encode(scope, "UTF-8")
            redirect_enc = URLEncoder.encode(redirect_uri, "UTF-8")
            nonce_enc    = URLEncoder.encode(nonce, "UTF-8")

            path = "%s?scope=%s&response_type=code&redirect_uri=%s&nonce=%s&client_id=%s" % (
                sso_path, scope_enc, redirect_enc, nonce_enc, client_id)

            host, port = self._parse_host_port(sso_domain)
            proto = "https" if port == 443 else "http"

            req = (
                "GET %s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "Connection: close\r\n"
                "Cookie: %s\r\n"
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36\r\n"
                "Accept: */*\r\n"
                "Accept-Encoding: identity\r\n"
                "Referer: https://%s/\r\n"
                "\r\n"
            ) % (path, host, sso_cookies, host)

            http_svc = self._helpers.buildHttpService(host, port, proto)
            req_bytes = self._helpers.stringToBytes(req)

            self._log("[Step 1] Authorize -> %s%s" % (host, sso_path))
            resp = self._callbacks.makeHttpRequest(http_svc, req_bytes)

            if resp is None:
                self._log("[Step 1] No response from SSO server")
                return None

            ri = self._helpers.analyzeResponse(resp)
            sc = ri.getStatusCode()

            if sc != 302:
                self._log("[Step 1] Expected 302, got %d. SSO cookies may be expired." % sc)
                body = resp[ri.getBodyOffset():]
                if body:
                    self._log("[Step 1] Body preview: %s" % self._helpers.bytesToString(body)[:300])
                return None

            location = None
            for h in ri.getHeaders():
                if h.lower().startswith("location:"):
                    location = h.split(":", 1)[1].strip()
                    break

            if not location:
                self._log("[Step 1] 302 without Location header")
                return None

            if "code=" not in location:
                self._log("[Step 1] Location has no 'code' param: %s" % location[:200])
                return None

            self._log("[Step 1] Got redirect URL (%d chars)" % len(location))
            return location

        except Exception as e:
            self._log("[Step 1] Exception: %s" % str(e))
            return None

    # -- Step 2 ---------------------------------------------------------

    def _step2_exchange_code(self, redirect_url, fallback_domain):
        """Returns (jsessionid, ingresscookie) or (None, None)."""
        try:
            url = URL(redirect_url)
            host = url.getHost()
            port = url.getPort()
            proto = url.getProtocol() or "https"
            if port == -1:
                port = 443 if proto == "https" else 80

            path  = url.getPath() or "/"
            query = url.getQuery()
            if query:
                req_path = "%s?%s" % (path, query)
            else:
                req_path = path

            sso_host = self._txt_sso_domain.getText().strip().split(":")[0]

            req = (
                "GET %s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "Connection: close\r\n"
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36\r\n"
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                "Accept-Language: en-US\r\n"
                "Accept-Encoding: identity\r\n"
                "Referer: https://%s/\r\n"
                "\r\n"
            ) % (req_path, host, sso_host)

            http_svc = self._helpers.buildHttpService(host, port, proto)
            req_bytes = self._helpers.stringToBytes(req)

            self._log("[Step 2] Exchange code -> %s%s" % (host, path))
            resp = self._callbacks.makeHttpRequest(http_svc, req_bytes)

            if resp is None:
                self._log("[Step 2] No response from main server")
                return None, None

            ri = self._helpers.analyzeResponse(resp)
            sc = ri.getStatusCode()

            if sc != 200:
                self._log("[Step 2] Expected 200, got %d" % sc)
                return None, None

            jsessionid = None
            ingresscookie = None
            for h in ri.getHeaders():
                h_lower = h.lower()
                if h_lower.startswith("set-cookie:"):
                    cookie_val = h.split(":", 1)[1].strip()
                    if "jsessionid" in h_lower:
                        m = re.search(r'JSESSIONID=([^;\s]+)', cookie_val, re.IGNORECASE)
                        if m:
                            jsessionid = m.group(1)
                    elif "ingresscookie" in h_lower:
                        m = re.search(r'INGRESSCOOKIE=([^;\s]+)', cookie_val, re.IGNORECASE)
                        if m:
                            ingresscookie = m.group(1)

            if not jsessionid:
                self._log("[Step 2] No JSESSIONID in Set-Cookie headers")
                return None, None

            self._log("[Step 2] JSESSIONID: %s... | INGRESSCOOKIE: %s" % (
                jsessionid[:15], ingresscookie[:15] if ingresscookie else "none"))
            return jsessionid, ingresscookie

        except Exception as e:
            self._log("[Step 2] Exception: %s" % str(e))
            return None, None

    # -- Step 3 ---------------------------------------------------------

    def _step3_get_token(self, main_domain, base_path, jsessionid):
        """Returns (token, ingresscookie) or (None, None)."""
        try:
            host, port = self._parse_host_port(main_domain)
            proto = "https" if port == 443 else "http"
            path  = "%s/token" % base_path

            req = (
                "GET %s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "Connection: close\r\n"
                "Cookie: JSESSIONID=%s\r\n"
                "Accept: application/json, text/plain, */*\r\n"
                "Accept-Language: en-US\r\n"
                "Accept-Encoding: identity\r\n"
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36\r\n"
                "\r\n"
            ) % (path, host, jsessionid)

            http_svc = self._helpers.buildHttpService(host, port, proto)
            req_bytes = self._helpers.stringToBytes(req)

            self._log("[Step 3] Fetch token -> %s%s" % (host, path))
            resp = self._callbacks.makeHttpRequest(http_svc, req_bytes)

            if resp is None:
                self._log("[Step 3] No response from token endpoint")
                return None, None

            ri = self._helpers.analyzeResponse(resp)
            sc = ri.getStatusCode()

            if sc != 200:
                self._log("[Step 3] Expected 200, got %d" % sc)
                return None, None

            # Capture INGRESSCOOKIE from Step 3 response (may be updated)
            ingresscookie = None
            for h in ri.getHeaders():
                h_lower = h.lower()
                if h_lower.startswith("set-cookie:") and "ingresscookie" in h_lower:
                    cookie_val = h.split(":", 1)[1].strip()
                    m = re.search(r'INGRESSCOOKIE=([^;\s]+)', cookie_val, re.IGNORECASE)
                    if m:
                        ingresscookie = m.group(1)

            body = resp[ri.getBodyOffset():]
            body_str = self._helpers.bytesToString(body)

            try:
                data = json.loads(body_str)
            except ValueError:
                self._log("[Step 3] Response is not valid JSON: %s" % body_str[:200])
                return None, None

            token = data.get("token") or data.get("access_token") or data.get("id_token")
            if not token:
                self._log("[Step 3] No token field in JSON: %s" % body_str[:200])
                return None, None

            self._log("[Step 3] Token obtained (%d chars)" % len(token))
            return token, ingresscookie

        except Exception as e:
            self._log("[Step 3] Exception: %s" % str(e))
            return None, None

    # ------------------------------------------------------------------
    # JWT helpers
    # ------------------------------------------------------------------

    def _decode_jwt_expiry(self, token):
        try:
            parts = token.split(".")
            if len(parts) < 2:
                return int(time.time()) + 3600
            payload_b64 = parts[1]
            pad = 4 - len(payload_b64) % 4
            if pad != 4:
                payload_b64 += "=" * pad
            payload_bytes = base64.urlsafe_b64decode(payload_b64)
            payload = json.loads(payload_bytes)
            exp = payload.get("exp", 0)
            if exp:
                return int(exp)
            return int(time.time()) + 3600
        except Exception as e:
            self._log("JWT decode error (using 1h default): %s" % str(e))
            return int(time.time()) + 3600

    def _decode_jwt_field(self, token, field):
        try:
            parts = token.split(".")
            if len(parts) < 2:
                return None
            payload_b64 = parts[1]
            pad = 4 - len(payload_b64) % 4
            if pad != 4:
                payload_b64 += "=" * pad
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            return payload.get(field)
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Header & Cookie manipulation
    # ------------------------------------------------------------------

    def _strip_headers(self, headers, names_to_remove):
        """
        Remove headers whose name matches any in names_to_remove.
        Returns (new_headers, changed).
        """
        names_lower = [n.lower() for n in names_to_remove]
        result = []
        changed = False
        for h in headers:
            if ":" not in h:
                result.append(h)
                continue
            name = h.split(":", 1)[0].strip().lower()
            if name in names_lower:
                changed = True
            else:
                result.append(h)
        return result, changed

    def _replace_cookie_value(self, headers, cookie_name, cookie_value):
        """
        Replace an EXISTING cookie value in the Cookie header.
        ONLY replaces if the cookie already exists in the request.
        NEVER forcefully adds a cookie that wasn't there - this is critical
        because injecting JSESSIONID into session-flow requests (like the
        code exchange) would prevent the server from issuing a new one.
        Returns (new_headers, changed).
        """
        result = []
        found_cookie_header = False
        changed = False

        for h in headers:
            if ":" not in h:
                result.append(h)
                continue
            name = h.split(":", 1)[0].strip().lower()
            if name == "cookie":
                found_cookie_header = True
                cookie_str = h.split(":", 1)[1].strip()
                new_cookie_str, did_replace = self._replace_cookie_in_string(
                    cookie_str, cookie_name, cookie_value)
                if did_replace:
                    changed = True
                result.append("Cookie: %s" % new_cookie_str)
            else:
                result.append(h)

        # Do NOT add a new Cookie header if none existed.
        # Do NOT append the cookie if it wasn't already present.
        # Only replace what was already there.

        return result, changed

    def _replace_cookie_in_string(self, cookie_str, cookie_name, cookie_value):
        """
        Parse a Cookie header value string, replace cookie_name if it exists.
        If cookie_name is NOT found, returns the string unchanged.
        Preserves all other cookies intact.
        Returns (new_cookie_string, was_replaced).
        """
        cookies = []
        found = False
        for part in cookie_str.split(";"):
            part = part.strip()
            if not part:
                continue
            if "=" in part:
                cname = part.split("=", 1)[0].strip()
                cval  = part.split("=", 1)[1].strip()
                if cname.lower() == cookie_name.lower():
                    cookies.append("%s=%s" % (cookie_name, cookie_value))
                    found = True
                else:
                    cookies.append("%s=%s" % (cname, cval))
            else:
                cookies.append(part)

        # If the cookie was not found, do NOT add it.
        # Return the original string unchanged.
        if not found:
            return cookie_str, False

        return "; ".join(cookies), True

    def _set_auth_header(self, headers, token):
        """Add or replace the Authorization: Bearer header. Returns (new_headers, changed)."""
        result = []
        replaced = False
        changed = False
        for h in headers:
            if ":" not in h:
                result.append(h)
                continue
            name = h.split(":", 1)[0].strip().lower()
            if name == "authorization":
                new_header = "Authorization: Bearer %s" % token
                if h != new_header:
                    changed = True
                result.append(new_header)
                replaced = True
            else:
                result.append(h)
        if not replaced:
            result.append("Authorization: Bearer %s" % token)
            changed = True
        return result, changed

    def _get_global_headers_to_remove(self):
        text = self._txt_headers_remove_global.getText().strip()
        if not text:
            return []
        return [line.strip() for line in text.split("\n") if line.strip()]

    def _get_domain_headers_to_remove(self):
        text = self._txt_headers_remove_domain.getText().strip()
        if not text:
            return []
        return [line.strip() for line in text.split("\n") if line.strip()]

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def _parse_host_port(self, domain):
        domain = domain.strip()
        if ":" in domain:
            parts = domain.rsplit(":", 1)
            try:
                return parts[0], int(parts[1])
            except ValueError:
                return parts[0], 443
        return domain, 443

    # ------------------------------------------------------------------
    # Swing UI
    # ------------------------------------------------------------------

    def _build_ui(self):
        self._main_panel = JPanel(BorderLayout(8, 8))
        self._main_panel.setBorder(EmptyBorder(8, 8, 8, 8))

        # Scrollable top section for config + controls
        top_content = JPanel(BorderLayout(8, 8))
        top_content.add(self._build_config_panel(), BorderLayout.CENTER)

        mid_panel = JPanel(BorderLayout(8, 8))
        mid_panel.add(self._build_scope_panel(), BorderLayout.WEST)
        mid_panel.add(self._build_control_panel(), BorderLayout.CENTER)
        top_content.add(mid_panel, BorderLayout.SOUTH)

        top_scroll = JScrollPane(top_content)
        top_scroll.setPreferredSize(Dimension(750, 420))
        top_scroll.setBorder(None)

        self._main_panel.add(top_scroll, BorderLayout.CENTER)
        self._main_panel.add(self._build_log_panel(), BorderLayout.SOUTH)

    # -- Configuration panel --------------------------------------------

    def _build_config_panel(self):
        panel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.insets = Insets(2, 4, 2, 4)

        row = [0]

        def add_row(label_text, default, cols=35, is_area=False, area_rows=3):
            gbc.gridx = 0; gbc.gridy = row[0]; gbc.weightx = 0
            lbl = JLabel(label_text)
            lbl.setHorizontalAlignment(JLabel.RIGHT)
            panel.add(lbl, gbc)

            gbc.gridx = 1; gbc.gridy = row[0]; gbc.weightx = 1; gbc.gridwidth = 3
            if is_area:
                comp = JTextArea(area_rows, cols)
                comp.setLineWrap(True)
                comp.setWrapStyleWord(True)
                comp.setText(default)
                sp = JScrollPane(comp)
                sp.setPreferredSize(Dimension(450, area_rows * 20))
                panel.add(sp, gbc)
            else:
                comp = JTextField(default, cols)
                panel.add(comp, gbc)

            gbc.gridwidth = 1
            row[0] += 1
            return comp

        self._txt_sso_domain   = add_row("SSO Domain:", "sso.example.com")
        self._txt_main_domain  = add_row("Main Domain:", "main.example.com")
        self._txt_client_id    = add_row("Client ID:", "")
        self._txt_redirect_uri = add_row("Redirect URI:", "https://main.example.com/transact-explorer-wa/")
        self._txt_scope        = add_row("Scope:", "openid profile")
        self._txt_sso_path     = add_row("SSO Auth Path:", "/sgconnect/oauth2/authorize")
        self._txt_base_path    = add_row("App Base Path:", "/transact-explorer-wa")
        self._txt_sso_cookies  = add_row("SSO Cookies:", "", is_area=True, area_rows=3)
        self._txt_headers_remove_global = add_row(
            "Headers to Remove\n(ALL requests):",
            "",
            is_area=True, area_rows=3
        )
        self._txt_headers_remove_domain = add_row(
            "Headers to Remove\n(Main Domain only):",
            "Sec-Fetch-Site\nSec-Fetch-Mode\nSec-Fetch-Dest\nsec-ch-ua\nsec-ch-ua-mobile\nsec-ch-ua-platform",
            is_area=True, area_rows=5
        )

        panel.setBorder(TitledBorder(
            BorderFactory.createEtchedBorder(EtchedBorder.LOWERED),
            "  Configuration  "
        ))
        return panel

    # -- Scope panel ----------------------------------------------------

    def _build_scope_panel(self):
        panel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.anchor = GridBagConstraints.WEST
        gbc.insets = Insets(1, 4, 1, 4)

        self._chk_proxy      = JCheckBox("Proxy  (use with caution)", True)
        self._chk_repeater   = JCheckBox("Repeater",  True)
        self._chk_intruder   = JCheckBox("Intruder",  True)
        self._chk_scanner    = JCheckBox("Scanner",   True)
        self._chk_sequencer  = JCheckBox("Sequencer", False)
        self._chk_extensions = JCheckBox("Extensions", False)
        self._chk_target     = JCheckBox("Target",    False)

        checkboxes = [
            self._chk_proxy, self._chk_repeater, self._chk_intruder,
            self._chk_scanner, self._chk_sequencer, self._chk_extensions,
            self._chk_target
        ]
        for i, cb in enumerate(checkboxes):
            gbc.gridx = 0; gbc.gridy = i
            panel.add(cb, gbc)

        panel.setBorder(TitledBorder(
            BorderFactory.createEtchedBorder(EtchedBorder.LOWERED),
            "  Tool Scope  "
        ))
        return panel

    # -- Control panel --------------------------------------------------

    def _build_control_panel(self):
        panel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(4, 6, 4, 6)
        gbc.fill = GridBagConstraints.HORIZONTAL

        btn_panel = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        self._btn_start   = JButton("Start",   actionPerformed=self._on_start)
        self._btn_stop    = JButton("Stop",    actionPerformed=self._on_stop)
        self._btn_refresh = JButton("Force Refresh", actionPerformed=self._on_force_refresh)
        self._btn_clear   = JButton("Clear Log",     actionPerformed=self._on_clear_log)

        self._btn_stop.setEnabled(False)
        self._btn_refresh.setEnabled(False)

        for b in [self._btn_start, self._btn_stop, self._btn_refresh, self._btn_clear]:
            btn_panel.add(b)

        self._lbl_status     = JLabel("Status: Stopped")
        self._lbl_status.setFont(Font("Monospaced", Font.BOLD, 12))
        self._lbl_token_info = JLabel("Token: NONE")
        self._lbl_token_info.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._lbl_expiry     = JLabel("Expires: N/A")
        self._lbl_expiry.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._lbl_refresh_ct = JLabel("Refreshes: 0")
        self._lbl_refresh_ct.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._lbl_session    = JLabel("JSESSIONID: N/A | INGRESSCOOKIE: N/A")
        self._lbl_session.setFont(Font("Monospaced", Font.PLAIN, 11))

        info_panel = JPanel(GridBagLayout())
        igbc = GridBagConstraints()
        igbc.anchor = GridBagConstraints.WEST
        igbc.insets = Insets(1, 4, 1, 4)

        labels = [self._lbl_status, self._lbl_token_info, self._lbl_expiry,
                  self._lbl_refresh_ct, self._lbl_session]
        for i, l in enumerate(labels):
            igbc.gridx = 0; igbc.gridy = i
            info_panel.add(l, igbc)

        gbc.gridx = 0; gbc.gridy = 0
        panel.add(btn_panel, gbc)
        gbc.gridx = 0; gbc.gridy = 1
        panel.add(info_panel, gbc)

        panel.setBorder(TitledBorder(
            BorderFactory.createEtchedBorder(EtchedBorder.LOWERED),
            "  Control  "
        ))
        return panel

    # -- Log panel ------------------------------------------------------

    def _build_log_panel(self):
        self._txt_log = JTextArea(8, 60)
        self._txt_log.setEditable(False)
        self._txt_log.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._txt_log.setLineWrap(True)
        sp = JScrollPane(self._txt_log)
        sp.setPreferredSize(Dimension(650, 160))
        sp.setBorder(TitledBorder(
            BorderFactory.createEtchedBorder(EtchedBorder.LOWERED),
            "  Log  "
        ))
        return sp

    # ------------------------------------------------------------------
    # Button handlers
    # ------------------------------------------------------------------

    def _on_start(self, event):
        missing = []
        if not self._txt_sso_domain.getText().strip():
            missing.append("SSO Domain")
        if not self._txt_main_domain.getText().strip():
            missing.append("Main Domain")
        if not self._txt_client_id.getText().strip():
            missing.append("Client ID")
        if not self._txt_redirect_uri.getText().strip():
            missing.append("Redirect URI")
        if not self._txt_sso_cookies.getText().strip():
            missing.append("SSO Cookies")
        if missing:
            self._log("Cannot start - missing: %s" % ", ".join(missing))
            return

        self._running = True
        self._btn_start.setEnabled(False)
        self._btn_stop.setEnabled(True)
        self._btn_refresh.setEnabled(True)
        self._log("Extension STARTED. Fetching initial token...")
        t = threading.Thread(target=self._bg_initial_fetch)
        t.setDaemon(True)
        t.start()

    def _on_stop(self, event):
        self._running = False
        self._btn_start.setEnabled(True)
        self._btn_stop.setEnabled(False)
        self._btn_refresh.setEnabled(False)
        self._edt_status("Stopped")
        self._log("Extension STOPPED.")

    def _on_force_refresh(self, event):
        self._invalidate_token()
        self._log("Force refresh requested...")
        t = threading.Thread(target=self._bg_refresh)
        t.setDaemon(True)
        t.start()

    def _on_clear_log(self, event):
        self._txt_log.setText("")

    # -- Background token fetch threads ---------------------------------

    def _bg_initial_fetch(self):
        with self._token_lock:
            self._do_refresh()
        self._update_session_label()

        t = threading.Thread(target=self._bg_expiry_monitor)
        t.setDaemon(True)
        t.start()

    def _bg_refresh(self):
        with self._token_lock:
            self._do_refresh()
        self._update_session_label()

    def _bg_expiry_monitor(self):
        """Background thread that updates the expiry label periodically."""
        while self._running:
            try:
                if self._token_cache and self._token_expiry > 0:
                    remaining = self._token_expiry - time.time()
                    if remaining > 0:
                        mins = int(remaining / 60)
                        secs = int(remaining % 60)
                        exp_str = time.strftime("%H:%M:%S", time.localtime(self._token_expiry))
                        self._edt_status("Running - Token valid until %s (%dm %ds left)" % (
                            exp_str, mins, secs))
                    else:
                        self._edt_status("Running - Token EXPIRED (will refresh on next request)")
            except Exception:
                pass
            time.sleep(15)

    def _update_session_label(self):
        try:
            jsid = self._jsessionid[:12] + "..." if self._jsessionid else "N/A"
            igc  = self._ingresscookie[:12] + "..." if self._ingresscookie else "N/A"
            text = "JSESSIONID: %s | INGRESSCOOKIE: %s" % (jsid, igc)
            SwingUtilities.invokeLater(_RunnableUpdateSession(self, text))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Logging & status helpers
    # ------------------------------------------------------------------

    def _log(self, msg):
        ts = time.strftime("%H:%M:%S")
        line = "[%s] %s" % (ts, msg)
        self._callbacks.printOutput(line)
        try:
            SwingUtilities.invokeLater(_RunnableAppendLog(self, line))
        except Exception:
            pass

    def _edt_status(self, text):
        try:
            SwingUtilities.invokeLater(_RunnableUpdateStatus(self, text))
        except Exception:
            pass

    def _update_token_info(self, text):
        try:
            SwingUtilities.invokeLater(_RunnableUpdateTokenInfo(self, text))
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Additional Runnable for session label
# ---------------------------------------------------------------------------

class _RunnableUpdateSession(object):
    def __init__(self, ext, text):
        self._ext = ext
        self._text = text
    def run(self):
        self._ext._lbl_session.setText(self._text)
