# -*- coding: utf-8 -*-
"""
OAuth Token Manager v6 - SURGICAL REPLACE-ONLY EDITION
Fixes: Strict in-place JSESSIONID replacement (NO ADDING). 
Applies to ALL URLs on Main Domain. No path exclusions.
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

        callbacks.setExtensionName("OAuth Token Manager v6")
        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)
        callbacks.registerExtensionStateListener(self)
        callbacks.registerContextMenuFactory(self)

        self._stdout.println("[OAuth Token Manager v6] Loaded. SURGICAL REPLACE-ONLY mode active.")

    def getTabCaption(self):
        return "OAuth Token Mgr"

    def getUiComponent(self):
        return self._main_panel

    # ========================================================================
    # CONTEXT MENU (REPEATER UI INJECTION)
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
            if not messages: return
            for msg in messages:
                req = msg.getRequest()
                if req:
                    strip_list = list(self._headers_to_remove_lower)
                    add_auth_headers = {}
                    replace_cookies = {}
                    
                    http_service = msg.getHttpService()
                    req_info = self._helpers.analyzeRequest(http_service, req)
                    host = req_info.getUrl().getHost().lower()
                    
                    main_domain = self._main_domain_field.getText().strip().lower()
                    api_domain = self._api_domain_field.getText().strip().lower()
                    
                    if main_domain and main_domain in host:
                        if self._jsessionid: replace_cookies["JSESSIONID"] = self._jsessionid
                    if api_domain and api_domain in host:
                        if self._ensure_token() and self._jwt_token: add_auth_headers["Authorization"] = "Bearer %s" % self._jwt_token
                        
                    if strip_list or add_auth_headers or replace_cookies:
                        msg.setRequest(self._modify_request(req, strip_list, add_auth_headers, replace_cookies))
                        self._log("UI UPDATED: Visually injected tokens into Editor.")
        except Exception as e:
            self._log("ERROR in context menu: %s" % str(e))

    # ========================================================================
    # UI CONSTRUCTION
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
        domain_panel.setBorder(BorderFactory.createTitledBorder("Domain Routing Configuration"))
        gbc = GridBagConstraints()
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.insets = Insets(4, 4, 4, 4)

        gbc.gridx = 0; gbc.gridy = 0
        domain_panel.add(JLabel("Main Domain (UI / JSESSIONID):"), gbc)
        gbc.gridx = 1; gbc.weightx = 1.0
        self._main_domain_field = JTextField(30)
        self._main_domain_field.setText("main.com")
        domain_panel.add(self._main_domain_field, gbc)

        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0.0
        domain_panel.add(JLabel("API Domain (Backend / JWT):"), gbc)
        gbc.gridx = 1; gbc.weightx = 1.0
        self._api_domain_field = JTextField(30)
        self._api_domain_field.setText("api.main.com")
        domain_panel.add(self._api_domain_field, gbc)

        gbc.gridx = 0; gbc.gridy = 2; gbc.weightx = 0.0
        domain_panel.add(JLabel("SSO Domain (Auth Flow):"), gbc)
        gbc.gridx = 1; gbc.weightx = 1.0
        self._sso_domain_field = JTextField(30)
        self._sso_domain_field.setText("sso.com")
        domain_panel.add(self._sso_domain_field, gbc)

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
        cookie_panel.add(JScrollPane(self._sso_cookie_area), BorderLayout.CENTER)
        center_panel.add(cookie_panel)
        center_panel.add(Box.createVerticalStrut(5))

        headers_panel = JPanel(BorderLayout())
        headers_panel.setBorder(BorderFactory.createTitledBorder("Headers to Remove (Global - one per line)"))
        self._headers_to_remove_area = JTextArea(3, 50)
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
        status_panel.add(JLabel("Licenses Used:"), gbc)
        gbc.gridx = 1; gbc.weightx = 1.0
        self._license_label = JLabel("0 / 30")
        self._license_label.setFont(Font("Monospaced", Font.BOLD, 12))
        status_panel.add(self._license_label, gbc)

        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0.0
        status_panel.add(JLabel("JWT Token (API):"), gbc)
        gbc.gridx = 1; gbc.weightx = 1.0
        self._jwt_status_label = JLabel("Not cached")
        status_panel.add(self._jwt_status_label, gbc)
        gbc.gridx = 2; gbc.weightx = 0.0
        self._copy_jwt_btn = JButton("Copy", actionPerformed=self._copy_jwt_clicked)
        status_panel.add(self._copy_jwt_btn, gbc)

        gbc.gridx = 0; gbc.gridy = 2; gbc.weightx = 0.0
        status_panel.add(JLabel("JSESSIONID (Main):"), gbc)
        gbc.gridx = 1; gbc.weightx = 1.0
        self._jsessionid_label = JLabel("Not cached")
        status_panel.add(self._jsessionid_label, gbc)

        gbc.gridx = 0; gbc.gridy = 3; gbc.weightx = 0.0
        status_panel.add(JLabel("Auth Status:"), gbc)
        gbc.gridx = 1; gbc.weightx = 1.0
        self._auth_status_label = JLabel("Idle")
        status_panel.add(self._auth_status_label, gbc)

        center_panel.add(status_panel)
        center_panel.add(Box.createVerticalStrut(5))

        log_panel = JPanel(BorderLayout())
        log_panel.setBorder(BorderFactory.createTitledBorder("Log"))
        self._log_area = JTextArea(8, 50)
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
    # IHttpListener (THE CORE ROUTING ENGINE)
    # ========================================================================

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not self._running: return
        if getattr(self._auth_local, 'in_progress', False): return
        if not self._is_tool_enabled(toolFlag): return

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
            host = url.getHost().lower()

            strip_list = list(self._headers_to_remove_lower)
            add_auth_headers = {}
            replace_cookies = {}
            
            main_domain = self._main_domain_field.getText().strip().lower()
            api_domain = self._api_domain_field.getText().strip().lower()
            
            # NO MORE PATH EXCLUSIONS. 
            # self._auth_local.in_progress already protects the extension's internal requests.
            # This ensures JSESSIONID is replaced on EVERY SINGLE URL on the main domain.
            
            # 1. ROUTE JSESSIONID TO MAIN DOMAIN (EVERYWHERE)
            if main_domain and main_domain in host:
                if self._jsessionid:
                    replace_cookies["JSESSIONID"] = self._jsessionid
                        
            # 2. ROUTE JWT TO API DOMAIN
            if api_domain and api_domain in host:
                if self._ensure_token() and self._jwt_token:
                    add_auth_headers["Authorization"] = "Bearer %s" % self._jwt_token

            if strip_list or add_auth_headers or replace_cookies:
                new_request = self._modify_request(request, strip_list, add_auth_headers, replace_cookies)
                messageInfo.setRequest(new_request)

        except Exception as e:
            self._log("ERROR in _process_request: %s" % str(e))

    def _process_response(self, messageInfo):
        try:
            response = messageInfo.getResponse()
            if response is None: return

            response_info = self._helpers.analyzeResponse(response)
            if response_info.getStatusCode() == 401:
                req_info = self._helpers.analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest())
                host = req_info.getUrl().getHost().lower()
                api_domain = self._api_domain_field.getText().strip().lower()
                
                if api_domain and api_domain in host:
                    self._log("ALERT: 401 on API Domain - invalidating JWT")
                    with self._auth_lock:
                        self._jwt_token = None
                        self._jwt_expiry = 0
                    self._update_status_ui()
        except Exception as e:
            pass

    # ========================================================================
    # SURGICAL REQUEST MODIFICATION (REPLACE ONLY - NO ADDING)
    # ========================================================================

    def _modify_request(self, request_bytes, strip_headers_lower=None, add_headers=None, replace_cookies=None):
        try:
            req_info = self._helpers.analyzeRequest(request_bytes)
            headers = list(req_info.getHeaders())
            body = request_bytes[req_info.getBodyOffset():]
            
            # 1. Strip global headers
            if strip_headers_lower:
                headers = [h for h in headers if not (":" in h and h.split(":")[0].strip().lower() in strip_headers_lower)]
                
            # 2. Add/Replace Auth Headers (API Domain)
            if add_headers:
                for name, value in add_headers.items():
                    headers = [h for h in headers if not (":" in h and h.split(":")[0].strip().lower() == name.lower())]
                    headers.append("%s: %s" % (name, value))
                    
            # 3. STRICT IN-PLACE JSESSIONID REPLACEMENT (Main Domain)
            # ONLY replaces if JSESSIONID is ALREADY in the original request. NO ADDING.
            if replace_cookies and "JSESSIONID" in replace_cookies:
                for i, h in enumerate(headers):
                    if h.lower().startswith("cookie:"):
                        cookie_header_val = h.split(":", 1)[1].strip()
                        new_cookie_parts = []
                        jsessionid_found_in_og = False
                        
                        for part in cookie_header_val.split(";"):
                            if "=" in part:
                                k, v = part.split("=", 1)
                                k_stripped = k.strip()
                                if k_stripped.upper() == "JSESSIONID":
                                    # SURGICAL REPLACEMENT
                                    new_cookie_parts.append("%s=%s" % (k_stripped, replace_cookies["JSESSIONID"]))
                                    jsessionid_found_in_og = True
                                else:
                                    new_cookie_parts.append(part.strip())
                            else:
                                if part.strip():
                                    new_cookie_parts.append(part.strip())
                                    
                        # ONLY rewrite the header if JSESSIONID was actually found in the original request
                        if jsessionid_found_in_og:
                            headers[i] = "Cookie: %s" % "; ".join(new_cookie_parts)
                        break
                        
            return self._helpers.buildHttpMessage(headers, body)
            
        except Exception as e:
            self._log("ERROR in _modify_request: %s" % str(e))
            return request_bytes

    # ========================================================================
    # LICENSE-SAFE TOKEN MANAGEMENT
    # ========================================================================

    def _ensure_token(self):
        if self._is_token_valid(): return True
        with self._auth_lock:
            if self._is_token_valid(): return True
            if self._jsessionid and self._jsessionid_alive:
                if self._jwt_refresh_only(): return True
            return self._full_authenticate()

    def _jwt_refresh_only(self):
        if not self._running or not self._jsessionid: return False
        self._auth_local.in_progress = True
        try:
            main_domain = self._main_domain_field.getText().strip()
            token_path = self._token_path_field.getText().strip()
            callback_path = self._callback_path_field.getText().strip()
            token_url = "https://%s%s" % (main_domain, token_path)
            
            response = self._make_request(token_url, {
                "Cookie": "JSESSIONID=%s" % self._jsessionid,
                "Accept": "application/json, text/plain, */*",
                "Referer": "https://%s%s" % (main_domain, callback_path),
            })
            if not response or not response.getResponse(): return False
            
            resp_info = self._helpers.analyzeResponse(response.getResponse())
            if resp_info.getStatusCode() in [301, 302, 303, 307]:
                self._jsessionid_alive = False
                return False
                
            if resp_info.getStatusCode() != 200: return False
            
            body_str = self._helpers.bytesToString(response.getResponse()[resp_info.getBodyOffset():])
            jwt = json.loads(body_str).get("token")
            if not jwt: return False
            
            self._jwt_token = jwt
            self._jwt_expiry = self._parse_jwt_expiry(jwt)
            self._jwt_refresh_count += 1
            self._update_status_ui()
            return True
        except: return False
        finally: self._auth_local.in_progress = False

    def _full_authenticate(self):
        if not self._running: return False
        self._auth_local.in_progress = True
        try:
            sso_domain = self._sso_domain_field.getText().strip()
            main_domain = self._main_domain_field.getText().strip()
            auth_path = self._authorize_path_field.getText().strip().replace("main.com", main_domain)
            callback_path = self._callback_path_field.getText().strip()
            token_path = self._token_path_field.getText().strip()
            sso_cookie = self._sso_cookie_area.getText().strip()

            r1 = self._make_request("https://%s%s" % (sso_domain, auth_path), {"Cookie": sso_cookie})
            if not r1 or not r1.getResponse(): return False
            loc = [h.split(":",1)[1].strip() for h in self._helpers.analyzeResponse(r1.getResponse()).getHeaders() if h.lower().startswith("location:")]
            if not loc: return False
            code = parse_qs(urlparse(loc[0]).query).get('code', [None])[0]
            if not code: return False

            r2 = self._make_request(loc[0], {"Referer": "https://%s/" % sso_domain})
            if not r2 or not r2.getResponse(): return False
            jsessionid = None
            for c in self._helpers.analyzeResponse(r2.getResponse()).getCookies():
                if c.getName() and "JSESSIONID" in c.getName().upper(): jsessionid = c.getValue()
            if not jsessionid: return False

            r3 = self._make_request("https://%s%s" % (main_domain, token_path), {
                "Cookie": "JSESSIONID=%s" % jsessionid, "Accept": "application/json", "Referer": "https://%s%s" % (main_domain, callback_path)
            })
            if not r3 or not r3.getResponse(): return False
            
            body_str = self._helpers.bytesToString(r3.getResponse()[self._helpers.analyzeResponse(r3.getResponse()).getBodyOffset():])
            jwt = json.loads(body_str).get("token")
            if not jwt: return False

            self._jwt_token = jwt
            self._jsessionid = jsessionid
            self._jwt_expiry = self._parse_jwt_expiry(jwt)
            self._jsessionid_alive = True
            self._full_auth_count += 1
            self._update_status_ui()
            return True
        except: return False
        finally: self._auth_local.in_progress = False

    def _make_request(self, url_str, extra_headers=None):
        try:
            url = URL(url_str)
            host = url.getHost()
            port = url.getPort() if url.getPort() != -1 else (443 if url.getProtocol() == "https" else 80)
            path = url.getPath() or "/"
            if url.getQuery(): path += "?" + url.getQuery()
                
            headers = ["GET %s HTTP/1.1" % path, "Host: %s" % host, "User-Agent: Mozilla/5.0", "Accept: */*", "Connection: close"]
            if extra_headers:
                for k, v in extra_headers.items(): headers.append("%s: %s" % (k, v))
                
            return self._callbacks.makeHttpRequest(self._helpers.buildHttpService(host, port, url.getProtocol() == "https"), self._helpers.buildHttpMessage(headers, None))
        except: return None

    def _parse_jwt_expiry(self, jwt):
        try:
            payload = jwt.split(".")[1]
            payload += "=" * (-len(payload) % 4)
            return int(json.loads(base64.b64decode(payload.replace("-", "+").replace("_", "/"))).get("exp", 0))
        except: return 0

    def _is_token_valid(self):
        if not self._jwt_token or not self._jsessionid: return False
        if self._jwt_expiry == 0: return True
        return time.time() < (self._jwt_expiry - 10)

    def _is_tool_enabled(self, tool_flag):
        for name, flag in self._tool_flags.items():
            if tool_flag & flag: return self._tool_checkboxes[name].isSelected()
        return True

    # ========================================================================
    # UI HANDLERS & PERSISTENCE
    # ========================================================================

    def _start_clicked(self, event):
        self._running = True
        self._start_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._update_headers_to_remove()
        SwingUtilities.invokeLater(lambda: self._status_label.setText("  Status: RUNNING  "))
        self._status_label.setForeground(Color(0, 128, 0))
        if self._sso_cookie_area.getText().strip() and not self._is_token_valid():
            threading.Thread(target=self._ensure_token).start()

    def _stop_clicked(self, event):
        self._running = False
        self._start_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        SwingUtilities.invokeLater(lambda: self._status_label.setText("  Status: STOPPED  "))
        self._status_label.setForeground(Color.RED)

    def _refresh_jwt_clicked(self, event):
        with self._auth_lock: self._jwt_token = None; self._jwt_expiry = 0
        threading.Thread(target=self._ensure_token).start()

    def _refresh_full_clicked(self, event):
        if JOptionPane.showConfirmDialog(self._main_panel, "Consume 1 license?", "Confirm", JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION:
            with self._auth_lock: self._jwt_token = None; self._jsessionid = None; self._jwt_expiry = 0; self._jsessionid_alive = False
            threading.Thread(target=self._full_authenticate).start()

    def _clear_clicked(self, event):
        with self._auth_lock: self._jwt_token = None; self._jsessionid = None; self._jwt_expiry = 0; self._jsessionid_alive = False
        self._update_status_ui()

    def _save_clicked(self, event): self._save_settings()
    def _copy_jwt_clicked(self, event):
        if self._jwt_token: Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection(self._jwt_token), None)
    def _clear_log_clicked(self, event): SwingUtilities.invokeLater(lambda: self._log_area.setText(""))

    def _save_settings(self):
        try:
            self._callbacks.saveExtensionSetting("oauth_v6", json.dumps({
                "sso": self._sso_domain_field.getText(), "main": self._main_domain_field.getText(), "api": self._api_domain_field.getText(),
                "auth": self._authorize_path_field.getText(), "cb": self._callback_path_field.getText(), "tok": self._token_path_field.getText(),
                "hdr": self._headers_to_remove_area.getText(), "tools": {n: c.isSelected() for n, c in self._tool_checkboxes.items()}
            }))
        except: pass

    def _load_settings(self):
        try:
            c = json.loads(self._callbacks.loadExtensionSetting("oauth_v6") or "{}")
            self._sso_domain_field.setText(c.get("sso", "sso.com"))
            self._main_domain_field.setText(c.get("main", "main.com"))
            self._api_domain_field.setText(c.get("api", "api.main.com"))
            self._authorize_path_field.setText(c.get("auth", ""))
            self._callback_path_field.setText(c.get("cb", "/transact-explorer-wa/"))
            self._token_path_field.setText(c.get("tok", "/transact-explorer-wa/token"))
            self._headers_to_remove_area.setText(c.get("hdr", ""))
            for n, cb in self._tool_checkboxes.items(): cb.setSelected(c.get("tools", {}).get(n, True))
        except: pass

    def _update_headers_to_remove(self):
        self._headers_to_remove_lower = set([l.strip().lower() for l in self._headers_to_remove_area.getText().split("\n") if l.strip()])

    def _update_status_ui(self):
        def update():
            self._license_label.setText("%d / 30" % self._full_auth_count)
            self._jwt_status_label.setText(self._jwt_token[:30] + "..." if self._jwt_token else "Not cached")
            self._jsessionid_label.setText(self._jsessionid[:40] + "..." if self._jsessionid else "Not cached")
        SwingUtilities.invokeLater(update)

    def _log(self, message):
        log_msg = "[%s] %s" % (datetime.now().strftime("%H:%M:%S"), message)
        SwingUtilities.invokeLater(lambda: self._log_area.append(log_msg + "\n"))
        self._stdout.println(log_msg)

    def extensionUnloaded(self):
        self._running = False
