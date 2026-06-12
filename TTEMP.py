# -*- coding: utf-8 -*-
"""
OAuth Token Manager v4 - THE FINAL BOSS
Fixes: Repeater UI Illusion, Infinite Refresh Spam, Context Menu Injection.
Compatible with: Burp Suite + Jython Standalone 2.7.4
"""

from burp import (IBurpExtender, IHttpListener, ITab, IExtensionStateListener, 
                  IBurpExtenderCallbacks, IContextMenuFactory, IContextMenuInvocation)

from java.io import PrintWriter
from java.awt import (BorderLayout, FlowLayout, GridBagLayout, GridBagConstraints,
                      Insets, Toolkit, Color, Font)
from java.awt.datatransfer import StringSelection
from java.net import URL
from javax.swing import (JPanel, JButton, JTextField, JLabel, JCheckBox,
                         JTextArea, JScrollPane, BorderFactory, BoxLayout,
                         SwingUtilities, JOptionPane, Box, JMenuItem)

import json
import base64
import time
import threading
from urlparse import urlparse, parse_qs
from datetime import datetime
from urllib import quote, unquote


class BurpExtender(IBurpExtender, IHttpListener, ITab, IExtensionStateListener, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        self._running = False
        self._jwt_token = None
        self._jsessionid = None
        self._jwt_expiry = 0
        self._jsessionid_alive = False
        self._full_auth_count = 0
        self._jwt_refresh_count = 0

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

        callbacks.setExtensionName("OAuth Token Manager v4")
        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)
        callbacks.registerExtensionStateListener(self)
        callbacks.registerContextMenuFactory(self)

        self._stdout.println("[OAuth Token Manager v4] FINAL BOSS extension loaded. Right-click in Repeater to inject!")

    def getTabCaption(self):
        return "OAuth Token Mgr"

    def getUiComponent(self):
        return self._main_panel

    # ========================================================================
    # CONTEXT MENU (THE REPEATER UI FIX)
    # ========================================================================

    def createMenuItems(self, invocation):
        menu_list = []
        context = invocation.getInvocationContext()
        if context == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR:
            menu_item = JMenuItem("Inject OAuth Token (Update UI)", actionPerformed=lambda e, inv=invocation: self._inject_ui(inv))
            menu_list.append(menu_item)
        return menu_list

    def _inject_ui(self, invocation):
        try:
            messages = invocation.getSelectedMessages()
            if not messages:
                return
            for msg in messages:
                req = msg.getRequest()
                if req:
                    strip_list = list(self._headers_to_remove_lower)
                    add_auth_headers = {}
                    replace_cookies = {}
                    
                    http_service = msg.getHttpService()
                    req_info = self._helpers.analyzeRequest(http_service, req)
                    host = req_info.getUrl().getHost()
                    main_domain = self._main_domain_field.getText().strip().lower()
                    
                    if main_domain and main_domain in host.lower():
                        if self._ensure_token():
                            add_auth_headers["Authorization"] = "Bearer %s" % self._jwt_token
                            replace_cookies["JSESSIONID"] = self._jsessionid
                            
                    if strip_list or add_auth_headers or replace_cookies:
                        new_req = self._modify_request(req, strip_list, add_auth_headers, replace_cookies)
                        msg.setRequest(new_req)
                        self._log("UI UPDATED: Injected token into Repeater/Editor visually.")
        except Exception as e:
            self._log("ERROR in context menu: %s" % str(e))

    # ========================================================================
    # UI
    # ========================================================================

    def _build_ui(self):
        self._main_panel = JPanel(BorderLayout(5, 5))
        self._main_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

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

        center_panel = JPanel()
        center_panel.setLayout(BoxLayout(center_panel, BoxLayout.Y_AXIS))

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

        cookie_panel = JPanel(BorderLayout())
        cookie_panel.setBorder(BorderFactory.createTitledBorder("SSO Cookie (Paste daily)"))
        self._sso_cookie_area = JTextArea(4, 50)
        self._sso_cookie_area.setLineWrap(True)
        self._sso_cookie_area.setWrapStyleWord(True)
        cookie_panel.add(JScrollPane(self._sso_cookie_area), BorderLayout.CENTER)
        center_panel.add(cookie_panel)
        center_panel.add(Box.createVerticalStrut(5))

        headers_panel = JPanel(BorderLayout())
        headers_panel.setBorder(BorderFactory.createTitledBorder("Headers to Remove (one per line)"))
        self._headers_to_remove_area = JTextArea(3, 50)
        self._headers_to_remove_area.setLineWrap(False)
        headers_panel.add(JScrollPane(self._headers_to_remove_area), BorderLayout.CENTER)
        center_panel.add(headers_panel)
        center_panel.add(Box.createVerticalStrut(5))

        tool_panel = JPanel(FlowLayout(FlowLayout.LEFT, 10, 5))
        tool_panel.setBorder(BorderFactory.createTitledBorder("Tool Scope"))
        for tool_name in ["Target", "Proxy", "Repeater", "Intruder", "Scanner", "Sequencer", "Extensions"]:
            cb = JCheckBox(tool_name, True)
            self._tool_checkboxes[tool_name] = cb
            tool_panel.add(cb)
        center_panel.add(tool_panel)
        center_panel.add(Box.createVerticalStrut(5))

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

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not self._running:
            return

        if getattr(self._auth_local, 'in_progress', False):
            return

        if not self._is_tool_enabled(toolFlag):
            return

        if messageIsRequest:
            self._process_request(messageInfo)
        else:
            self._process_response(messageInfo)

    def _process_request(self, messageInfo):
        try:
            request = messageInfo.getRequest()
            http_service = messageInfo.getHttpService()
            request_info = self._helpers.analyzeRequest(http_service, request)
            url = request_info.getUrl()
            host = url.getHost()
            path = url.getPath()

            strip_list = list(self._headers_to_remove_lower)
            add_auth_headers = {}
            replace_cookies = {}
            
            main_domain = self._main_domain_field.getText().strip().lower()
            if main_domain and main_domain in host.lower():
                token_path = self._token_path_field.getText().strip()
                callback_path = self._callback_path_field.getText().strip()
                
                is_auth_flow = (token_path and path.startswith(token_path)) or \
                               (callback_path and path.startswith(callback_path))
                               
                if not is_auth_flow:
                    if self._ensure_token():
                        add_auth_headers["Authorization"] = "Bearer %s" % self._jwt_token
                        replace_cookies["JSESSIONID"] = self._jsessionid

            if strip_list or add_auth_headers or replace_cookies:
                new_request = self._modify_request(request, strip_list, add_auth_headers, replace_cookies)
                messageInfo.setRequest(new_request)

        except Exception as e:
            self._log("ERROR in _process_request: %s" % str(e))

    def _process_response(self, messageInfo):
        try:
            response = messageInfo.getResponse()
            if response is None:
                return

            response_info = self._helpers.analyzeResponse(response)
            status_code = response_info.getStatusCode()

            if status_code == 401:
                request_info = self._helpers.analyzeRequest(
                    messageInfo.getHttpService(), messageInfo.getRequest())
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

    def _modify_request(self, request_bytes, strip_headers_lower=None, add_headers=None, replace_cookies=None):
        try:
            req_info = self._helpers.analyzeRequest(request_bytes)
            headers = list(req_info.getHeaders())
            body = request_bytes[req_info.getBodyOffset():]
            
            if strip_headers_lower:
                headers = [h for h in headers if not (":" in h and h.split(":")[0].strip().lower() in strip_headers_lower)]
                
            if add_headers:
                for name, value in add_headers.items():
                    headers = [h for h in headers if not (":" in h and h.split(":")[0].strip().lower() == name.lower())]
                    headers.append("%s: %s" % (name, value))
                    
            if replace_cookies:
                cookie_idx = -1
                cookie_header_val = None
                for i, h in enumerate(headers):
                    if h.lower().startswith("cookie:"):
                        cookie_header_val = h.split(":", 1)[1].strip()
                        cookie_idx = i
                        break
                        
                cookies = {}
                if cookie_header_val:
                    for part in cookie_header_val.split(";"):
                        if "=" in part:
                            k, v = part.split("=", 1)
                            cookies[k.strip()] = v.strip()
                            
                cookies.update(replace_cookies)
                new_cookie_str = "; ".join(["%s=%s" % (k, v) for k, v in cookies.items()])
                
                if cookie_idx != -1:
                    headers[cookie_idx] = "Cookie: %s" % new_cookie_str
                else:
                    headers.append("Cookie: %s" % new_cookie_str)
                    
            return self._helpers.buildHttpMessage(headers, body)
            
        except Exception as e:
            self._log("ERROR in _modify_request: %s" % str(e))
            return request_bytes

    # ========================================================================
    # LICENSE-SAFE TOKEN MANAGEMENT
    # ========================================================================

    def _ensure_token(self):
        if self._is_token_valid():
            return True

        with self._auth_lock:
            if self._is_token_valid():
                return True

            if self._jsessionid and self._jsessionid_alive:
                self._log("STRATEGY: JWT-only refresh (no license cost)")
                result = self._jwt_refresh_only()
                if result:
                    return True

            self._log("STRATEGY: Full auth flow (costs 1 license)")
            return self._full_authenticate()

    def _jwt_refresh_only(self):
        if not self._running or not self._jsessionid:
            return False

        self._auth_local.in_progress = True
        self._update_auth_status("JWT Refresh (Free)...")

        try:
            main_domain = self._main_domain_field.getText().strip()
            token_path = self._token_path_field.getText().strip()
            callback_path = self._callback_path_field.getText().strip()

            if not all([main_domain, token_path, self._jsessionid]):
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
                self._update_auth_status("JWT Refresh FAILED")
                return False

            resp_bytes = response.getResponse()
            resp_info = self._helpers.analyzeResponse(resp_bytes)
            status = resp_info.getStatusCode()

            if status in [301, 302, 303, 307]:
                self._log("DETECTED 302 on /token -> JSESSIONID is EXPIRED/DEAD")
                self._jsessionid_alive = False
                self._update_jsessionid_status("DEAD (302 redirect)")
                return False

            if status != 200:
                self._update_auth_status("JWT Refresh FAILED (%d)" % status)
                return False

            body_offset = resp_info.getBodyOffset()
            body_bytes = resp_bytes[body_offset:]
            body_str = self._helpers.bytesToString(body_bytes)

            try:
                data = json.loads(body_str)
            except Exception as e:
                return False

            jwt = data.get("token")
            if not jwt:
                return False

            self._jwt_token = jwt
            self._jwt_expiry = self._parse_jwt_expiry(jwt)
            self._jwt_refresh_count += 1

            self._update_auth_status("JWT Refreshed (Free)")
            self._update_status_ui()
            return True

        except Exception as e:
            self._log("ERROR in _jwt_refresh_only: %s" % str(e))
            return False

        finally:
            self._auth_local.in_progress = False

    def _full_authenticate(self):
        if not self._running:
            return False

        self._auth_local.in_progress = True
        self._update_auth_status("Full Auth (Uses License)...")

        try:
            sso_domain = self._sso_domain_field.getText().strip()
            main_domain = self._main_domain_field.getText().strip()
            auth_path = self._authorize_path_field.getText().strip()
            callback_path = self._callback_path_field.getText().strip()
            token_path = self._token_path_field.getText().strip()
            sso_cookie = self._sso_cookie_area.getText().strip()

            if not all([sso_domain, main_domain, auth_path, token_path, sso_cookie]):
                self._update_auth_status("FAILED (config)")
                return False

            auth_path = auth_path.replace("main.com", main_domain)

            auth_url = "https://%s%s" % (sso_domain, auth_path)
            response1 = self._make_request(auth_url, {"Cookie": sso_cookie})

            if response1 is None or response1.getResponse() is None: return False
            resp1_info = self._helpers.analyzeResponse(response1.getResponse())
            if resp1_info.getStatusCode() not in [301, 302, 303, 307]: return False

            location = None
            for header in resp1_info.getHeaders():
                if header.lower().startswith("location:"):
                    location = header.split(":", 1)[1].strip()
                    break
            if not location: return False

            parsed_loc = urlparse(location)
            params = parse_qs(parsed_loc.query)
            code = params.get('code', [None])[0]
            if not code: return False

            response2 = self._make_request(location, {"Referer": "https://%s/" % sso_domain})
            if response2 is None or response2.getResponse() is None: return False
            resp2_info = self._helpers.analyzeResponse(response2.getResponse())
            if resp2_info.getStatusCode() not in [200, 301, 302]: return False

            jsessionid = None
            for cookie in resp2_info.getCookies():
                if cookie.getName() and "JSESSIONID" in cookie.getName().upper():
                    jsessionid = cookie.getValue()
                    break

            if not jsessionid: return False

            token_url = "https://%s%s" % (main_domain, token_path)
            response3 = self._make_request(token_url, {
                "Cookie": "JSESSIONID=%s" % jsessionid,
                "Accept": "application/json, text/plain, */*",
                "Referer": "https://%s%s" % (main_domain, callback_path),
            })

            if response3 is None or response3.getResponse() is None: return False
            resp3_info = self._helpers.analyzeResponse(response3.getResponse())
            if resp3_info.getStatusCode() != 200: return False

            body_offset = resp3_info.getBodyOffset()
            body_str = self._helpers.bytesToString(response3.getResponse()[body_offset:])

            try:
                data = json.loads(body_str)
            except: return False

            jwt = data.get("token")
            if not jwt: return False

            self._jwt_token = jwt
            self._jsessionid = jsessionid
            self._jwt_expiry = self._parse_jwt_expiry(jwt)
            self._jsessionid_alive = True
            self._full_auth_count += 1

            self._update_auth_status("SUCCESS (License #%d)" % self._full_auth_count)
            self._update_jsessionid_status("ALIVE")
            self._update_status_ui()
            return True

        except Exception as e:
            self._log("CRITICAL ERROR: %s" % str(e))
            return False

        finally:
            self._auth_local.in_progress = False

    def _make_request(self, url_str, extra_headers=None):
        try:
            url = URL(url_str)
            host = url.getHost()
            port = url.getPort()
            use_https = url.getProtocol() == "https"
            if port == -1: port = 443 if use_https else 80

            path = url.getPath()
            if not path: path = "/"
            query = url.getQuery()
            if query: path += "?" + query
                
            headers = [
                "GET %s HTTP/1.1" % path,
                "Host: %s" % host,
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept: */*",
                "Connection: close"
            ]
            if extra_headers:
                for k, v in extra_headers.items():
                    headers.append("%s: %s" % (k, v))
                    
            request = self._helpers.buildHttpMessage(headers, None)
            http_service = self._helpers.buildHttpService(host, port, use_https)
            return self._callbacks.makeHttpRequest(http_service, request)
        except Exception as e:
            return None

    def _parse_jwt_expiry(self, jwt):
        try:
            parts = jwt.split(".")
            if len(parts) != 3: return 0
            payload = parts[1]
            remainder = len(payload) % 4
            if remainder == 2: payload += "=="
            elif remainder == 3: payload += "="
            payload = payload.replace("-", "+").replace("_", "/")
            decoded = base64.b64decode(payload)
            data = json.loads(decoded)
            return int(data.get("exp", 0))
        except: return 0

    def _is_token_valid(self):
        if not self._jwt_token or not self._jsessionid: return False
        if self._jwt_expiry == 0: return True
        return time.time() < (self._jwt_expiry - 10)

    def _is_tool_enabled(self, tool_flag):
        for name, flag in self._tool_flags.items():
            if tool_flag & flag:
                return self._tool_checkboxes[name].isSelected()
        return True

    def _start_clicked(self, event):
        self._running = True
        self._start_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._update_headers_to_remove()
        def update():
            self._status_label.setText("  Status: RUNNING  ")
            self._status_label.setForeground(Color(0, 128, 0))
        SwingUtilities.invokeLater(update)
        self._log("Extension STARTED. Right-click in Repeater to inject manually, or just send requests.")
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

    def _refresh_jwt_clicked(self, event):
        with self._auth_lock:
            self._jwt_token = None
            self._jwt_expiry = 0
        threading.Thread(target=self._ensure_token).start()

    def _refresh_full_clicked(self, event):
        confirm = JOptionPane.showConfirmDialog(self._main_panel, "Consume 1 license?", "Confirm", JOptionPane.YES_NO_OPTION)
        if confirm == JOptionPane.YES_OPTION:
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

    def _save_clicked(self, event):
        self._save_settings()

    def _copy_jwt_clicked(self, event):
        if self._jwt_token:
            selection = StringSelection(self._jwt_token)
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, None)

    def _clear_log_clicked(self, event):
        def update(): self._log_area.setText("")
        SwingUtilities.invokeLater(update)

    def _save_settings(self):
        try:
            settings = {
                "sso_domain": self._sso_domain_field.getText(), "main_domain": self._main_domain_field.getText(),
                "auth_path": self._authorize_path_field.getText(), "callback_path": self._callback_path_field.getText(),
                "token_path": self._token_path_field.getText(), "headers_to_remove": self._headers_to_remove_area.getText(),
                "tools": {name: cb.isSelected() for name, cb in self._tool_checkboxes.items()}
            }
            self._callbacks.saveExtensionSetting("oauth_config_v4", json.dumps(settings))
        except: pass

    def _load_settings(self):
        try:
            config_str = self._callbacks.loadExtensionSetting("oauth_config_v4")
            if config_str:
                config = json.loads(config_str)
                self._sso_domain_field.setText(config.get("sso_domain", "sso.com"))
                self._main_domain_field.setText(config.get("main_domain", "main.com"))
                self._authorize_path_field.setText(config.get("auth_path", ""))
                self._callback_path_field.setText(config.get("callback_path", "/transact-explorer-wa/"))
                self._token_path_field.setText(config.get("token_path", "/transact-explorer-wa/token"))
                self._headers_to_remove_area.setText(config.get("headers_to_remove", ""))
                for name, cb in self._tool_checkboxes.items(): cb.setSelected(config.get("tools", {}).get(name, True))
        except: pass

    def _update_headers_to_remove(self):
        text = self._headers_to_remove_area.getText().strip()
        self._headers_to_remove_lower = set([l.strip().lower() for l in text.split("\n") if l.strip()])

    def _update_status_ui(self):
        def update():
            self._license_label.setText("%d / 30" % self._full_auth_count)
            self._jwt_refresh_label.setText(str(self._jwt_refresh_count))
            self._jwt_status_label.setText(self._jwt_token[:30] + "..." if self._jwt_token else "Not cached")
            self._jsessionid_label.setText(self._jsessionid[:40] + "..." if self._jsessionid else "Not cached")
            if self._jwt_expiry > 0:
                remaining = self._jwt_expiry - time.time()
                self._expiry_label.setText("%s (%dm left)" % (datetime.fromtimestamp(self._jwt_expiry).strftime("%H:%M:%S"), int(remaining/60)) if remaining > 0 else "EXPIRED")
            else: self._expiry_label.setText("N/A")
        SwingUtilities.invokeLater(update)

    def _update_jsessionid_status(self, status):
        def update():
            self._jsessionid_status_label.setText(status)
            self._jsessionid_status_label.setForeground(Color(0, 128, 0) if "ALIVE" in status else Color.RED if "DEAD" in status else Color.GRAY)
        SwingUtilities.invokeLater(update)

    def _update_auth_status(self, status):
        def update():
            self._auth_status_label.setText(status)
            self._auth_status_label.setForeground(Color(0, 128, 0) if "SUCCESS" in status else Color.RED if "FAIL" in status or "ERROR" in status else Color(0, 0, 200))
        SwingUtilities.invokeLater(update)

    def _log(self, message):
        log_msg = "[%s] %s" % (datetime.now().strftime("%H:%M:%S"), message)
        def update():
            self._log_area.append(log_msg + "\n")
            self._log_area.setCaretPosition(self._log_area.getDocument().getLength())
        SwingUtilities.invokeLater(update)
        self._stdout.println(log_msg)

    def extensionUnloaded(self):
        self._running = False
