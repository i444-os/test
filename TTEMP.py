"""
OAuth Token Manager v2 - License-Safe Edition
Prevents license exhaustion by separating JWT refresh from full auth flow.

Compatible with: Burp Suite + Jython Standalone 2.7.4
"""

from burp import IBurpExtender, IHttpListener, ITab, IExtensionStateListener

from java.io import PrintWriter
from java.awt import (BorderLayout, FlowLayout, GridBagLayout, GridBagConstraints,
                      Insets, Toolkit, Color, Font)
from java.awt.datatransfer import StringSelection
from java.net import URL
from javax.swing import (JPanel, JButton, JTextField, JLabel, JCheckBox,
                         JTextArea, JScrollPane, BorderFactory, BoxLayout,
                         SwingUtilities, JOptionPane, Box)

import json
import base64
import time
import threading
from urlparse import urlparse, parse_qs
from datetime import datetime
from urllib import quote, unquote


class BurpExtender(IBurpExtender, IHttpListener, ITab, IExtensionStateListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        # === STATE ===
        self._running = False
        self._jwt_token = None
        self._jsessionid = None
        self._jwt_expiry = 0
        self._jsessionid_alive = False  # Track if JSESSIONID is known to be valid
        self._full_auth_count = 0       # License usage counter
        self._jwt_refresh_count = 0     # Free refresh counter

        self._auth_lock = threading.Lock()
        self._auth_local = threading.local()

        self._headers_to_remove_lower = set()

        self._tool_flags = {
            "Target": IBurpExtenderCallbacks.TOOL_TARGET,
            "Intruder": IBurpExtenderCallbacks.TOOL_INTRUDER,
            "Extensions": IBurpExtenderCallbacks.TOOL_EXTENDER,
            "Scanner": IBurpExtenderCallbacks.TOOL_SCANNER,
            "Sequencer": IBurpExtenderCallbacks.TOOL_SEQUENCER,
            "Proxy": IBurpExtenderCallbacks.TOOL_PROXY,
            "Repeater": IBurpExtenderCallbacks.TOOL_REPEATER,
        }
        self._tool_checkboxes = {}

        self._build_ui()
        self._load_settings()

        callbacks.setExtensionName("OAuth Token Manager v2")
        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)
        callbacks.registerExtensionStateListener(self)

        self._stdout.println("[OAuth Token Manager v2] License-safe extension loaded")

    # ========================================================================
    # ITab
    # ========================================================================

    def getTabCaption(self):
        return "OAuth Token Mgr"

    def getUiComponent(self):
        return self._main_panel

    # ========================================================================
    # UI
    # ========================================================================

    def _build_ui(self):
        self._main_panel = JPanel(BorderLayout(5, 5))
        self._main_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        # ---- TOP: Controls ----
        top_panel = JPanel(FlowLayout(FlowLayout.LEFT, 5, 5))
        top_panel.setBorder(BorderFactory.createTitledBorder("Controls"))

        self._start_btn = JButton("Start", actionPerformed=self._start_clicked)
        self._stop_btn = JButton("Stop", actionPerformed=self._stop_clicked)
        self._stop_btn.setEnabled(False)
        self._refresh_jwt_btn = JButton("Refresh JWT Only (Free)", actionPerformed=self._refresh_jwt_clicked)
        self._refresh_full_btn = JButton("Full Auth (Uses 1 License)", actionPerformed=self._refresh_full_clicked)
        self._clear_btn = JButton("Clear Cache", actionPerformed=self._clear_clicked)
        self._save_btn = JButton("Save Settings", actionPerformed=self._save_clicked)

        self._status_label = JLabel("  Status: STOPPED  ")
        self._status_label.setForeground(Color.RED)

        top_panel.add(self._start_btn)
        top_panel.add(self._stop_btn)
        top_panel.add(self._refresh_jwt_btn)
        top_panel.add(self._refresh_full_btn)
        top_panel.add(self._clear_btn)
        top_panel.add(self._save_btn)
        top_panel.add(self._status_label)

        self._main_panel.add(top_panel, BorderLayout.NORTH)

        # ---- CENTER ----
        center_panel = JPanel()
        center_panel.setLayout(BoxLayout(center_panel, BoxLayout.Y_AXIS))

        # -- Domains --
        domain_panel = JPanel(GridBagLayout())
        domain_panel.setBorder(BorderFactory.createTitledBorder("Domain Configuration"))
        gbc = GridBagConstraints()
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.insets = Insets(4, 4, 4, 4)

        gbc.gridx = 0; gbc.gridy = 0
        domain_panel.add(JLabel("SSO Domain (actual):"), gbc)
        gbc.gridx = 1; gbc.weightx = 1.0
        self._sso_domain_field = JTextField(30)
        self._sso_domain_field.setText("sso.com")
        domain_panel.add(self._sso_domain_field, gbc)

        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0.0
        domain_panel.add(JLabel("Main Domain (actual):"), gbc)
        gbc.gridx = 1; gbc.weightx = 1.0
        self._main_domain_field = JTextField(30)
        self._main_domain_field.setText("main.com")
        domain_panel.add(self._main_domain_field, gbc)

        center_panel.add(domain_panel)
        center_panel.add(Box.createVerticalStrut(5))

        # -- OAuth Paths --
        oauth_panel = JPanel(GridBagLayout())
        oauth_panel.setBorder(BorderFactory.createTitledBorder("OAuth Path Configuration"))
        gbc = GridBagConstraints()
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.insets = Insets(4, 4, 4, 4)

        gbc.gridx = 0; gbc.gridy = 0
        oauth_panel.add(JLabel("Authorize Path (full with query):"), gbc)
        gbc.gridx = 1; gbc.weightx = 1.0
        self._authorize_path_field = JTextField(50)
        self._authorize_path_field.setText("/sgconnect/oauth2/authorize?scope=openid+profile&response_type=code&redirect_uri=https%3A%2F%2Fmain.com%2Ftransact-explorer-wa%2F&client_id=4f08fd1b-65b9-4a17-a700-ab249c060a05")
        oauth_panel.add(self._authorize_path_field, gbc)

        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0.0
        oauth_panel.add(JLabel("Callback Path:"), gbc)
        gbc.gridx = 1; gbc.weightx = 1.0
        self._callback_path_field = JTextField(50)
        self._callback_path_field.setText("/transact-explorer-wa/")
        oauth_panel.add(self._callback_path_field, gbc)

        gbc.gridx = 0; gbc.gridy = 2; gbc.weightx = 0.0
        oauth_panel.add(JLabel("Token Path:"), gbc)
        gbc.gridx = 1; gbc.weightx = 1.0
        self._token_path_field = JTextField(50)
        self._token_path_field.setText("/transact-explorer-wa/token")
        oauth_panel.add(self._token_path_field, gbc)

        center_panel.add(oauth_panel)
        center_panel.add(Box.createVerticalStrut(5))

        # -- SSO Cookie --
        cookie_panel = JPanel(BorderLayout())
        cookie_panel.setBorder(BorderFactory.createTitledBorder("SSO Cookie (Paste daily - the big cookie from 1st request)"))
        self._sso_cookie_area = JTextArea(4, 50)
        self._sso_cookie_area.setLineWrap(True)
        self._sso_cookie_area.setWrapStyleWord(True)
        cookie_panel.add(JScrollPane(self._sso_cookie_area), BorderLayout.CENTER)
        center_panel.add(cookie_panel)
        center_panel.add(Box.createVerticalStrut(5))

        # -- Headers to Remove --
        headers_panel = JPanel(BorderLayout())
        headers_panel.setBorder(BorderFactory.createTitledBorder("Headers to Remove (one per line, removed from ALL requests except auth flow)"))
        self._headers_to_remove_area = JTextArea(3, 50)
        self._headers_to_remove_area.setLineWrap(False)
        headers_panel.add(JScrollPane(self._headers_to_remove_area), BorderLayout.CENTER)
        center_panel.add(headers_panel)
        center_panel.add(Box.createVerticalStrut(5))

        # -- Tool Scope --
        tool_panel = JPanel(FlowLayout(FlowLayout.LEFT, 10, 5))
        tool_panel.setBorder(BorderFactory.createTitledBorder("Tool Scope"))
        for tool_name in ["Target", "Proxy", "Repeater", "Intruder", "Scanner", "Sequencer", "Extensions"]:
            cb = JCheckBox(tool_name, True)
            self._tool_checkboxes[tool_name] = cb
            tool_panel.add(cb)
        center_panel.add(tool_panel)
        center_panel.add(Box.createVerticalStrut(5))

        # -- License & Token Status --
        status_panel = JPanel(GridBagLayout())
        status_panel.setBorder(BorderFactory.createTitledBorder("License & Token Status"))
        gbc = GridBagConstraints()
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.insets = Insets(3, 3, 3, 3)

        gbc.gridx = 0; gbc.gridy = 0
        status_panel.add(JLabel("Licenses Used (Full Auths):"), gbc)
        gbc.gridx = 1; gbc.weightx = 1.0
        self._license_label = JLabel("0 / 30")
        self._license_label.setFont(Font("Monospaced", Font.BOLD, 12))
        status_panel.add(self._license_label, gbc)

        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0.0
        status_panel.add(JLabel("Free JWT Refreshes:"), gbc)
        gbc.gridx = 1; gbc.weightx = 1.0
        self._jwt_refresh_label = JLabel("0")
        status_panel.add(self._jwt_refresh_label, gbc)

        gbc.gridx = 0; gbc.gridy = 2; gbc.weightx = 0.0
        status_panel.add(JLabel("JWT Token:"), gbc)
        gbc.gridx = 1; gbc.weightx = 1.0
        self._jwt_status_label = JLabel("Not cached")
        status_panel.add(self._jwt_status_label, gbc)
        gbc.gridx = 2; gbc.weightx = 0.0
        self._copy_jwt_btn = JButton("Copy", actionPerformed=self._copy_jwt_clicked)
        status_panel.add(self._copy_jwt_btn, gbc)

        gbc.gridx = 0; gbc.gridy = 3; gbc.weightx = 0.0
        status_panel.add(JLabel("JSESSIONID:"), gbc)
        gbc.gridx = 1; gbc.weightx = 1.0
        self._jsessionid_label = JLabel("Not cached")
        status_panel.add(self._jsessionid_label, gbc)

        gbc.gridx = 0; gbc.gridy = 4; gbc.weightx = 0.0
        status_panel.add(JLabel("JSESSIONID Status:"), gbc)
        gbc.gridx = 1; gbc.weightx = 1.0
        self._jsessionid_status_label = JLabel("Unknown")
        status_panel.add(self._jsessionid_status_label, gbc)

        gbc.gridx = 0; gbc.gridy = 5; gbc.weightx = 0.0
        status_panel.add(JLabel("JWT Expires:"), gbc)
        gbc.gridx = 1; gbc.weightx = 1.0
        self._expiry_label = JLabel("N/A")
        status_panel.add(self._expiry_label, gbc)

        gbc.gridx = 0; gbc.gridy = 6; gbc.weightx = 0.0
        status_panel.add(JLabel("Auth Status:"), gbc)
        gbc.gridx = 1; gbc.weightx = 1.0
        self._auth_status_label = JLabel("Idle")
        status_panel.add(self._auth_status_label, gbc)

        center_panel.add(status_panel)
        center_panel.add(Box.createVerticalStrut(5))

        # -- Log --
        log_panel = JPanel(BorderLayout())
        log_panel.setBorder(BorderFactory.createTitledBorder("Log"))
        self._log_area = JTextArea(10, 50)
        self._log_area.setEditable(False)
        self._log_area.setFont(Font("Monospaced", Font.PLAIN, 11))
        log_panel.add(JScrollPane(self._log_area), BorderLayout.CENTER)

        clear_log_btn = JButton("Clear Log", actionPerformed=self._clear_log_clicked)
        log_panel.add(clear_log_btn, BorderLayout.SOUTH)
        center_panel.add(log_panel)

        scroll_pane = JScrollPane(center_panel)
        scroll_pane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED)
        scroll_pane.getVerticalScrollBar().setUnitIncrement(16)
        self._main_panel.add(scroll_pane, BorderLayout.CENTER)

    # ========================================================================
    # IHttpListener
    # ========================================================================

    def processHttpMessage(self, message_info):
        if not self._running:
            return

        if getattr(self._auth_local, 'in_progress', False):
            return

        request = message_info.getRequest()
        if request is None:
            return

        tool_flag = message_info.getToolFlag()
        if not self._is_tool_enabled(tool_flag):
            return

        response = message_info.getResponse()

        if response is None:
            self._process_request(message_info)
        else:
            self._process_response(message_info)

    def _process_request(self, message_info):
        try:
            request = message_info.getRequest()
            http_service = message_info.getHttpService()
            request_info = self._helpers.analyzeRequest(http_service, request)
            url = request_info.getUrl()
            host = url.getHost()

            request = self._strip_headers(request)

            main_domain = self._main_domain_field.getText().strip().lower()
            if main_domain and main_domain in host.lower():
                # Skip auth flow URLs themselves
                path = url.getPath()
                token_path = self._token_path_field.getText().strip()
                callback_path = self._callback_path_field.getText().strip()

                is_auth_flow = (token_path and path.startswith(token_path)) or \
                               (callback_path and path.startswith(callback_path))

                if not is_auth_flow:
                    if not self._ensure_token():
                        self._log("WARN: Cannot add auth for: %s" % path)
                    else:
                        request = self._add_auth(request)

            message_info.setRequest(request)

        except Exception as e:
            self._log("ERROR in _process_request: %s" % str(e))

    def _process_response(self, message_info):
        try:
            response = message_info.getResponse()
            if response is None:
                return

            response_info = self._helpers.analyzeResponse(response)
            status_code = response_info.getStatusCode()

            if status_code == 401:
                request_info = self._helpers.analyzeRequest(
                    message_info.getHttpService(), message_info.getRequest())
                url = request_info.getUrl()
                main_domain = self._main_domain_field.getText().strip().lower()

                if main_domain and main_domain in url.getHost().lower():
                    self._log("ALERT: 401 for %s - invalidating JWT" % url.getPath())
                    with self._auth_lock:
                        self._jwt_token = None
                        self._jwt_expiry = 0
                    self._update_status_ui()

        except Exception as e:
            self._log("ERROR in _process_response: %s" % str(e))

    # ========================================================================
    # LICENSE-SAFE TOKEN MANAGEMENT (THE CRITICAL FIX)
    # ========================================================================

    def _ensure_token(self):
        """
        Double-checked locking with LICENSE-SAFE refresh strategy:
        1. If JWT valid → return True (no network call)
        2. If JWT expired but JSESSIONID alive → JWT-only refresh (FREE, no license)
        3. If JSESSIONID dead → Full auth (costs 1 license)
        """
        if self._is_token_valid():
            return True

        with self._auth_lock:
            if self._is_token_valid():
                return True

            # Strategy 1: Try JWT-only refresh if JSESSIONID is alive
            if self._jsessionid and self._jsessionid_alive:
                self._log("STRATEGY: JWT-only refresh (no license cost)")
                result = self._jwt_refresh_only()
                if result:
                    return True
                # If JWT refresh failed (302), JSESSIONID is dead → fall through to full auth

            # Strategy 2: Full auth (costs 1 license)
            self._log("STRATEGY: Full auth flow (costs 1 license)")
            return self._full_authenticate()

    def _jwt_refresh_only(self):
        """
        Refresh JWT using EXISTING JSESSIONID (Step 3 only).
        Returns True on success, False if JSESSIONID is dead (302 detected).
        DOES NOT consume a license.
        """
        if not self._running or not self._jsessionid:
            return False

        self._auth_local.in_progress = True
        self._update_auth_status("JWT Refresh (Free)...")
        self._log("Refreshing JWT only (Step 3/3) - no new JSESSIONID")

        try:
            main_domain = self._main_domain_field.getText().strip()
            token_path = self._token_path_field.getText().strip()
            callback_path = self._callback_path_field.getText().strip()

            if not all([main_domain, token_path, self._jsessionid]):
                self._log("FAIL: Missing config for JWT refresh")
                return False

            token_url = "https://%s%s" % (main_domain, token_path)
            self._log("GET %s" % token_url[:80])

            step3_headers = {
                "Cookie": "JSESSIONID=%s" % self._jsessionid,
                "Accept": "application/json, text/plain, */*",
                "Referer": "https://%s%s" % (main_domain, callback_path),
            }

            response = self._make_request(token_url, step3_headers)

            if response is None or response.getResponse() is None:
                self._log("FAIL: No response from /token")
                self._update_auth_status("JWT Refresh FAILED")
                return False

            resp_bytes = response.getResponse()
            resp_info = self._helpers.analyzeResponse(resp_bytes)
            status = resp_info.getStatusCode()

            # KEY DETECTION: 302 means JSESSIONID is DEAD
            if status in [301, 302, 303, 307]:
                self._log("DETECTED 302 on /token → JSESSIONID is EXPIRED/DEAD")
                self._log("Will need full auth on next attempt (costs 1 license)")
                self._jsessionid_alive = False
                self._update_jsessionid_status("DEAD (302 redirect)")
                self._update_auth_status("JSESSIONID Dead → Need Full Auth")
                return False

            if status != 200:
                self._log("FAIL: /token returned %d (expected 200)" % status)
                self._update_auth_status("JWT Refresh FAILED (%d)" % status)
                return False

            # Parse JWT from response
            body_offset = resp_info.getBodyOffset()
            body_bytes = resp_bytes[body_offset:]
            body_str = self._helpers.bytesToString(body_bytes)

            try:
                data = json.loads(body_str)
            except Exception as e:
                self._log("FAIL: Invalid JSON from /token: %s" % str(e))
                return False

            jwt = data.get("token")
            if not jwt:
                self._log("FAIL: No 'token' in JSON response")
                return False

            # Cache the new JWT (JSESSIONID stays the same!)
            self._jwt_token = jwt
            self._jwt_expiry = self._parse_jwt_expiry(jwt)
            self._jwt_refresh_count += 1

            expiry_str = datetime.fromtimestamp(self._jwt_expiry).strftime("%H:%M:%S") if self._jwt_expiry > 0 else "?"
            self._log("JWT REFRESH SUCCESS! (Free refresh #%d) Expires: %s" % (self._jwt_refresh_count, expiry_str))
            self._update_auth_status("JWT Refreshed (Free)")
            self._update_status_ui()
            return True

        except Exception as e:
            self._log("ERROR in _jwt_refresh_only: %s" % str(e))
            import traceback
            self._log(traceback.format_exc())
            return False

        finally:
            self._auth_local.in_progress = False

    def _full_authenticate(self):
        """
        Full 3-step OAuth flow. COSTS 1 LICENSE.
        Only called when JSESSIONID is dead or missing.
        """
        if not self._running:
            return False

        # License warning
        if self._full_auth_count >= 25:
            self._log("WARNING: Approaching license limit (%d/30 used)!" % self._full_auth_count)

        self._auth_local.in_progress = True
        self._update_auth_status("Full Auth (Uses License)...")
        self._log("=" * 50)
        self._log("FULL AUTH FLOW (Steps 1+2+3) - WILL consume 1 license")

        try:
            sso_domain = self._sso_domain_field.getText().strip()
            main_domain = self._main_domain_field.getText().strip()
            auth_path = self._authorize_path_field.getText().strip()
            callback_path = self._callback_path_field.getText().strip()
            token_path = self._token_path_field.getText().strip()
            sso_cookie = self._sso_cookie_area.getText().strip()

            if not all([sso_domain, main_domain, auth_path, token_path, sso_cookie]):
                self._log("FAIL: Missing configuration")
                self._update_auth_status("FAILED (config)")
                return False

            auth_path = auth_path.replace("main.com", main_domain)

            # === STEP 1: SSO Authorize ===
            if not self._running:
                return False

            auth_url = "https://%s%s" % (sso_domain, auth_path)
            self._log("Step 1/3: GET %s" % auth_url[:80])

            response1 = self._make_request(auth_url, {"Cookie": sso_cookie})

            if response1 is None or response1.getResponse() is None:
                self._log("FAIL Step 1: No response")
                return False

            resp1_info = self._helpers.analyzeResponse(response1.getResponse())
            status1 = resp1_info.getStatusCode()

            if status1 not in [301, 302, 303, 307]:
                self._log("FAIL Step 1: Expected 3xx, got %d. Check SSO cookie!" % status1)
                self._update_auth_status("FAILED (Step 1: %d)" % status1)
                return False

            location = None
            for header in resp1_info.getHeaders():
                if header.lower().startswith("location:"):
                    location = header.split(":", 1)[1].strip()
                    break

            if not location:
                self._log("FAIL Step 1: No Location header")
                return False

            parsed_loc = urlparse(location)
            params = parse_qs(parsed_loc.query)
            code = params.get('code', [None])[0]

            if not code:
                self._log("FAIL Step 1: No 'code' in redirect URL")
                return False

            self._log("Step 1 OK: code=%s..." % code[:20])

            # === STEP 2: Callback (creates JSESSIONID = consumes license) ===
            if not self._running:
                return False

            callback_url = location
            self._log("Step 2/3: GET %s [THIS CREATES NEW JSESSIONID = 1 LICENSE]" % callback_url[:60])

            response2 = self._make_request(callback_url, {
                "Referer": "https://%s/" % sso_domain,
            })

            if response2 is None or response2.getResponse() is None:
                self._log("FAIL Step 2: No response")
                return False

            resp2_info = self._helpers.analyzeResponse(response2.getResponse())
            status2 = resp2_info.getStatusCode()

            if status2 not in [200, 301, 302]:
                self._log("FAIL Step 2: Expected 200, got %d" % status2)
                return False

            # Extract JSESSIONID
            jsessionid = None
            for cookie in resp2_info.getCookies():
                name = cookie.getName()
                if name and "JSESSIONID" in name.upper():
                    jsessionid = cookie.getValue()
                    break

            if not jsessionid:
                for header in resp2_info.getHeaders():
                    if header.lower().startswith("set-cookie:") and "jsessionid" in header.lower():
                        parts = header.split(":", 1)[1].strip().split(";")
                        for part in parts:
                            if "=" in part:
                                k, v = part.split("=", 1)
                                if "jsessionid" in k.strip().lower():
                                    jsessionid = v.strip()
                                    break
                        if jsessionid:
                            break

            if not jsessionid:
                self._log("FAIL Step 2: No JSESSIONID in response")
                return False

            self._log("Step 2 OK: JSESSIONID=%s... [LICENSE CONSUMED]" % jsessionid[:20])

            # === STEP 3: Token Request ===
            if not self._running:
                return False

            token_url = "https://%s%s" % (main_domain, token_path)
            self._log("Step 3/3: GET %s" % token_url[:80])

            response3 = self._make_request(token_url, {
                "Cookie": "JSESSIONID=%s" % jsessionid,
                "Accept": "application/json, text/plain, */*",
                "Referer": "https://%s%s" % (main_domain, callback_path),
            })

            if response3 is None or response3.getResponse() is None:
                self._log("FAIL Step 3: No response")
                return False

            resp3_info = self._helpers.analyzeResponse(response3.getResponse())
            status3 = resp3_info.getStatusCode()

            if status3 != 200:
                self._log("FAIL Step 3: Expected 200, got %d" % status3)
                return False

            body_offset = resp3_info.getBodyOffset()
            body_str = self._helpers.bytesToString(response3.getResponse()[body_offset:])

            try:
                data = json.loads(body_str)
            except Exception as e:
                self._log("FAIL Step 3: Invalid JSON: %s" % str(e))
                return False

            jwt = data.get("token")
            if not jwt:
                self._log("FAIL Step 3: No 'token' in JSON")
                return False

            # === CACHE EVERYTHING ===
            self._jwt_token = jwt
            self._jsessionid = jsessionid
            self._jwt_expiry = self._parse_jwt_expiry(jwt)
            self._jsessionid_alive = True
            self._full_auth_count += 1

            expiry_str = datetime.fromtimestamp(self._jwt_expiry).strftime("%H:%M:%S") if self._jwt_expiry > 0 else "?"
            self._log("FULL AUTH SUCCESS! (License #%d/30 used) JWT expires: %s" % (self._full_auth_count, expiry_str))
            self._log("=" * 50)

            self._update_auth_status("SUCCESS (License #%d)" % self._full_auth_count)
            self._update_jsessionid_status("ALIVE")
            self._update_status_ui()
            return True

        except Exception as e:
            self._log("CRITICAL ERROR: %s" % str(e))
            import traceback
            self._log(traceback.format_exc())
            self._update_auth_status("ERROR")
            return False

        finally:
            self._auth_local.in_progress = False

    # ========================================================================
    # HTTP Helpers
    # ========================================================================

    def _make_request(self, url_str, extra_headers=None):
        try:
            url = URL(url_str)
            host = url.getHost()
            port = url.getPort()
            use_https = url.getProtocol() == "https"

            if port == -1:
                port = 443 if use_https else 80

            request = self._helpers.buildHttpRequest(url)
            request = self._helpers.addHeader(request,
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36")
            request = self._helpers.addHeader(request, "Accept: */*")
            request = self._helpers.addHeader(request, "Accept-Language: en-US")
            request = self._helpers.addHeader(request, "sec-ch-ua: \"Not;A=Brand\";v=\"24\", \"Chromium\";v=\"128\"")
            request = self._helpers.addHeader(request, "sec-ch-ua-mobile: ?0")
            request = self._helpers.addHeader(request, "sec-ch-ua-platform: \"Windows\"")

            if extra_headers:
                for k, v in extra_headers.items():
                    request = self._helpers.addHeader(request, "%s: %s" % (k, v))

            http_service = self._helpers.buildHttpService(host, port, use_https)
            return self._callbacks.makeHttpRequest(http_service, request)

        except Exception as e:
            self._log("ERROR _make_request %s: %s" % (url_str[:50], str(e)))
            return None

    def _strip_headers(self, request_bytes):
        if not self._headers_to_remove_lower:
            return request_bytes
        try:
            request_info = self._helpers.analyzeRequest(request_bytes)
            to_remove = []
            for header in request_info.getHeaders():
                if ":" in header:
                    name = header.split(":")[0].strip()
                    if name.lower() in self._headers_to_remove_lower:
                        to_remove.append(name)
            for name in to_remove:
                request_bytes = self._helpers.removeHeader(request_bytes, name)
        except Exception as e:
            self._log("ERROR stripping headers: %s" % str(e))
        return request_bytes

    def _add_auth(self, request_bytes):
        try:
            request_bytes = self._helpers.removeHeader(request_bytes, "Authorization")
            request_bytes = self._helpers.addHeader(request_bytes,
                "Authorization: Bearer %s" % self._jwt_token)

            request_info = self._helpers.analyzeRequest(request_bytes)
            cookie_header_value = None
            for header in request_info.getHeaders():
                if header.lower().startswith("cookie:"):
                    cookie_header_value = header.split(":", 1)[1].strip()
                    break

            cookies_ordered = []
            if cookie_header_value:
                for cookie_part in cookie_header_value.split(";"):
                    cookie_part = cookie_part.strip()
                    if "=" in cookie_part:
                        name = cookie_part.split("=", 1)[0].strip()
                        value = cookie_part.split("=", 1)[1].strip()
                        if name.upper() != "JSESSIONID":
                            cookies_ordered.append((name, value))

            cookies_ordered.append(("JSESSIONID", self._jsessionid))
            cookie_str = "; ".join(["%s=%s" % (n, v) for n, v in cookies_ordered])

            request_bytes = self._helpers.removeHeader(request_bytes, "Cookie")
            request_bytes = self._helpers.addHeader(request_bytes, "Cookie: %s" % cookie_str)

        except Exception as e:
            self._log("ERROR adding auth: %s" % str(e))
        return request_bytes

    # ========================================================================
    # Utilities
    # ========================================================================

    def _parse_jwt_expiry(self, jwt):
        try:
            parts = jwt.split(".")
            if len(parts) != 3:
                return 0
            payload = parts[1]
            remainder = len(payload) % 4
            if remainder == 2:
                payload += "=="
            elif remainder == 3:
                payload += "="
            payload = payload.replace("-", "+").replace("_", "/")
            decoded = base64.b64decode(payload)
            data = json.loads(decoded)
            return int(data.get("exp", 0))
        except Exception as e:
            self._log("WARN: Cannot parse JWT expiry: %s" % str(e))
            return 0

    def _is_token_valid(self):
        if not self._jwt_token or not self._jsessionid:
            return False
        if self._jwt_expiry == 0:
            return True
        return time.time() < (self._jwt_expiry - 60)

    def _is_tool_enabled(self, tool_flag):
        for name, flag in self._tool_flags.items():
            if tool_flag & flag:
                return self._tool_checkboxes[name].isSelected()
        return True

    # ========================================================================
    # Button Handlers
    # ========================================================================

    def _start_clicked(self, event):
        self._running = True
        self._start_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._update_headers_to_remove()

        def update():
            self._status_label.setText("  Status: RUNNING  ")
            self._status_label.setForeground(Color(0, 128, 0))
        SwingUtilities.invokeLater(update)

        self._log("Extension STARTED")

        self._refresh_thread = threading.Thread(target=self._refresh_loop)
        self._refresh_thread.daemon = True
        self._refresh_thread.start()

        sso_cookie = self._sso_cookie_area.getText().strip()
        if sso_cookie and not self._is_token_valid():
            threading.Thread(target=self._ensure_token).start()

    def _stop_clicked(self, event):
        self._running = False
        self._start_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)

        def update():
            self._status_label.setText("  Status: STOPPED  ")
            self._status_label.setForeground(Color.RED)
        SwingUtilities.invokeLater(update)
        self._log("Extension STOPPED")

    def _refresh_jwt_clicked(self, event):
        """Manual JWT-only refresh (FREE - no license)"""
        self._log("Manual JWT-only refresh requested (free)")
        with self._auth_lock:
            self._jwt_token = None
            self._jwt_expiry = 0
        threading.Thread(target=self._ensure_token).start()

    def _refresh_full_clicked(self, event):
        """Manual full auth (costs 1 license)"""
        confirm = JOptionPane.showConfirmDialog(
            self._main_panel,
            "This will consume 1 license (current: %d/30).\nAre you sure?" % self._full_auth_count,
            "Confirm Full Auth",
            JOptionPane.YES_NO_OPTION)

        if confirm == JOptionPane.YES_OPTION:
            self._log("Manual FULL auth requested (costs 1 license)")
            with self._auth_lock:
                self._jwt_token = None
                self._jsessionid = None
                self._jwt_expiry = 0
                self._jsessionid_alive = False
            threading.Thread(target=self._full_authenticate).start()

    def _clear_clicked(self, event):
        with self._auth_lock:
            self._jwt_token = None
            self._jsessionid = None
            self._jwt_expiry = 0
            self._jsessionid_alive = False
        self._update_status_ui()
        self._log("Token cache cleared (license counter NOT reset)")

    def _save_clicked(self, event):
        self._save_settings()
        self._log("Settings saved")

    def _copy_jwt_clicked(self, event):
        if self._jwt_token:
            try:
                selection = StringSelection(self._jwt_token)
                clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
                clipboard.setContents(selection, None)
                self._log("JWT copied to clipboard")
            except Exception as e:
                self._log("Failed to copy: %s" % str(e))
        else:
            self._log("No JWT to copy")

    def _clear_log_clicked(self, event):
        def update():
            self._log_area.setText("")
        SwingUtilities.invokeLater(update)

    # ========================================================================
    # Background Refresh
    # ========================================================================

    def _refresh_loop(self):
        while self._running:
            try:
                time.sleep(15)
                if not self._running:
                    break

                if self._jwt_token and self._jwt_expiry > 0:
                    time_remaining = self._jwt_expiry - time.time()
                    if time_remaining < 120:
                        self._log("Proactive refresh: JWT expires in %ds (will try free refresh first)" % int(time_remaining))
                        with self._auth_lock:
                            self._jwt_token = None
                            self._jwt_expiry = 0
                        # This will try JWT-only first, then full if needed
                        self._ensure_token()

            except Exception as e:
                if self._running:
                    self._log("Refresh loop error: %s" % str(e))

    # ========================================================================
    # Settings
    # ========================================================================

    def _save_settings(self):
        try:
            settings = {
                "sso_domain": self._sso_domain_field.getText(),
                "main_domain": self._main_domain_field.getText(),
                "auth_path": self._authorize_path_field.getText(),
                "callback_path": self._callback_path_field.getText(),
                "token_path": self._token_path_field.getText(),
                "headers_to_remove": self._headers_to_remove_area.getText(),
                "tools": {}
            }
            for name, cb in self._tool_checkboxes.items():
                settings["tools"][name] = cb.isSelected()
            self._callbacks.saveExtensionSetting("oauth_config_v2", json.dumps(settings))
        except Exception as e:
            self._log("Save failed: %s" % str(e))

    def _load_settings(self):
        try:
            config_str = self._callbacks.loadExtensionSetting("oauth_config_v2")
            if config_str:
                config = json.loads(config_str)
                self._sso_domain_field.setText(config.get("sso_domain", "sso.com"))
                self._main_domain_field.setText(config.get("main_domain", "main.com"))
                self._authorize_path_field.setText(config.get("auth_path", ""))
                self._callback_path_field.setText(config.get("callback_path", "/transact-explorer-wa/"))
                self._token_path_field.setText(config.get("token_path", "/transact-explorer-wa/token"))
                self._headers_to_remove_area.setText(config.get("headers_to_remove", ""))
                tools = config.get("tools", {})
                for name, cb in self._tool_checkboxes.items():
                    cb.setSelected(tools.get(name, True))
                self._stdout.println("[OAuth Token Manager v2] Settings loaded")
        except Exception as e:
            self._stdout.println("[OAuth Token Manager v2] Load failed: %s" % str(e))

    # ========================================================================
    # UI Updates
    # ========================================================================

    def _update_headers_to_remove(self):
        text = self._headers_to_remove_area.getText().strip()
        self._headers_to_remove_lower = set()
        if text:
            for line in text.split("\n"):
                line = line.strip()
                if line:
                    self._headers_to_remove_lower.add(line.lower())

    def _update_status_ui(self):
        def update():
            # License counter (RED when near limit)
            self._license_label.setText("%d / 30" % self._full_auth_count)
            if self._full_auth_count >= 25:
                self._license_label.setForeground(Color.RED)
            elif self._full_auth_count >= 20:
                self._license_label.setForeground(Color(200, 128, 0))
            else:
                self._license_label.setForeground(Color(0, 128, 0))

            self._jwt_refresh_label.setText(str(self._jwt_refresh_count))

            if self._jwt_token:
                self._jwt_status_label.setText(self._jwt_token[:30] + "...")
            else:
                self._jwt_status_label.setText("Not cached")

            if self._jsessionid:
                self._jsessionid_label.setText(self._jsessionid[:40] + "...")
            else:
                self._jsessionid_label.setText("Not cached")

            if self._jwt_expiry > 0:
                exp_dt = datetime.fromtimestamp(self._jwt_expiry)
                remaining = self._jwt_expiry - time.time()
                if remaining > 0:
                    mins = int(remaining / 60)
                    self._expiry_label.setText("%s (%dm left)" % (exp_dt.strftime("%H:%M:%S"), mins))
                else:
                    self._expiry_label.setText("EXPIRED")
            else:
                self._expiry_label.setText("N/A")

        SwingUtilities.invokeLater(update)

    def _update_jsessionid_status(self, status):
        def update():
            self._jsessionid_status_label.setText(status)
            if "ALIVE" in status:
                self._jsessionid_status_label.setForeground(Color(0, 128, 0))
            elif "DEAD" in status:
                self._jsessionid_status_label.setForeground(Color.RED)
            else:
                self._jsessionid_status_label.setForeground(Color.GRAY)
        SwingUtilities.invokeLater(update)

    def _update_auth_status(self, status):
        def update():
            self._auth_status_label.setText(status)
            if "SUCCESS" in status:
                self._auth_status_label.setForeground(Color(0, 128, 0))
            elif "FAIL" in status or "ERROR" in status or "Dead" in status:
                self._auth_status_label.setForeground(Color.RED)
            else:
                self._auth_status_label.setForeground(Color(0, 0, 200))
        SwingUtilities.invokeLater(update)

    # ========================================================================
    # Logging
    # ========================================================================

    def _log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_msg = "[%s] %s" % (timestamp, message)

        def update():
            self._log_area.append(log_msg + "\n")
            line_count = self._log_area.getLineCount()
            if line_count > 500:
                try:
                    end_offset = self._log_area.getLineEndOffset(100)
                    self._log_area.replaceRange("", 0, end_offset)
                except:
                    pass
            self._log_area.setCaretPosition(self._log_area.getDocument().getLength())

        SwingUtilities.invokeLater(update)
        self._stdout.println(log_msg)

    # ========================================================================
    # Lifecycle
    # ========================================================================

    def extensionUnloaded(self):
        self._running = False
        self._stdout.println("[OAuth Token Manager v2] Unloaded")
