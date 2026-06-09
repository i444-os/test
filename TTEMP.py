# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener, ITab
from java.io import PrintWriter
import json
import re
import threading
import time
import base64
import java.lang

# Swing imports for the Burp UI Tab
from javax.swing import JPanel, JTextField, JTextArea, JCheckBox, JButton, JLabel, BoxLayout, JScrollPane, BorderFactory
from java.awt import GridLayout, Dimension

class BurpExtender(IBurpExtender, IHttpListener, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        callbacks.setExtensionName("SSO Auto Refresher & Injector")
        
        # Default configurations (Overridden by UI)
        self.sso_url = "https://sso.com/sgconnect/oauth2/authorize?scope=openid%20profile&response_type=code&redirect_uri=https://host.com/explorer-wa/&nonce=MTc4MDk4MTM1MTY50A%3D%3D&client_id=XXXXXXXXXXXXXXXX"
        self.sso_cookies = "SGX_tid=XXXXXXXXXXXXXXXXXXXXXXXX; sgx-11=XXXXXXXXXXXXXXXX; OAUTH_REQUEST_ATTRIBUTES=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX; SGX_PRD_authN_sticky_id=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX; amlbcookie=01; 12=XXXXXXXXXXXX"
        self.token_url = "https://host.com/explore-wa/token"
        
        self.enabled_tools = ["Target", "Intruder", "Extensions", "Scanner", "Sequencer", "Repeater", "Burp AI"]
        self.max_token_age = 10 # Minutes

        self._jsessionid = None
        self._jwt_token = None
        self.token_fetch_time = 0.0

        self._refresh_lock = threading.Lock()
        self._last_refresh = 0.0

        self._re_jsessionid = re.compile(r'JSESSIONID=([^;,\s]+)', re.IGNORECASE)
        self._re_scheme = re.compile(r'^https?://')
        self._re_path = re.compile(r'^https?://[^/]+(.*)')

        self._build_ui()
        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)

        self._stdout.println("[+] SSO Auto Refresher & Injector loaded. Configure in the 'SSO Refresher' tab.")

    # ----------------------------------------------------------
    # UI CONSTRUCTION
    # ----------------------------------------------------------
    def _build_ui(self):
        self.main_panel = JPanel()
        self.main_panel.setLayout(BoxLayout(self.main_panel, BoxLayout.Y_AXIS))
        
        config_panel = JPanel()
        config_panel.setLayout(BoxLayout(config_panel, BoxLayout.Y_AXIS))
        config_panel.setBorder(BorderFactory.createTitledBorder("SSO Configuration"))
        
        config_panel.add(JLabel("SSO URL:"))
        self.sso_url_field = JTextField(self.sso_url)
        self.sso_url_field.setMaximumSize(Dimension(1000, 30))
        config_panel.add(self.sso_url_field)
        
        config_panel.add(JLabel("SSO Cookies:"))
        self.cookies_field = JTextArea(self.sso_cookies, 3, 50)
        self.cookies_field.setLineWrap(True)
        self.cookies_field.setWrapStyleWord(True)
        config_panel.add(JScrollPane(self.cookies_field))
        
        config_panel.add(JLabel("Token Endpoint URL:"))
        self.token_url_field = JTextField(self.token_url)
        self.token_url_field.setMaximumSize(Dimension(1000, 30))
        config_panel.add(self.token_url_field)

        config_panel.add(JLabel("Max Token Age (minutes) - Proactive refresh to prevent 401s:"))
        self.max_age_field = JTextField(str(self.max_token_age))
        self.max_age_field.setMaximumSize(Dimension(1000, 30))
        config_panel.add(self.max_age_field)
        
        tool_panel = JPanel()
        tool_panel.setLayout(GridLayout(0, 2, 10, 10))
        tool_panel.setBorder(BorderFactory.createTitledBorder("Active Burp Tools (Where to inject & refresh)"))
        
        self.tool_checks = {}
        tools = ["Target", "Intruder", "Extensions", "Scanner", "Sequencer", "Proxy", "Repeater", "Burp AI"]
        
        for tool in tools:
            cb = JCheckBox(tool)
            cb.setSelected(tool in self.enabled_tools)
            self.tool_checks[tool] = cb
            tool_panel.add(cb)
            
        self.apply_btn = JButton("Apply Settings", actionPerformed=self._apply_settings)
        self.apply_btn.setMaximumSize(Dimension(200, 40))
        
        self.main_panel.add(config_panel)
        self.main_panel.add(tool_panel)
        self.main_panel.add(self.apply_btn)
        self.main_panel.add(JPanel())

    def _apply_settings(self, event):
        self.sso_url = self.sso_url_field.getText().strip()
        self.sso_cookies = self.cookies_field.getText().strip()
        self.token_url = self.token_url_field.getText().strip()
        
        try:
            self.max_token_age = int(self.max_age_field.getText().strip())
        except:
            self.max_token_age = 10
        
        self.enabled_tools = []
        for tool, cb in self.tool_checks.items():
            if cb.isSelected():
                self.enabled_tools.append(tool)
                
        self._stdout.println("[*] Settings applied. Active tools: " + ", ".join(self.enabled_tools))

    def getTabCaption(self):
        return "SSO Refresher"
        
    def getUiComponent(self):
        return self.main_panel

    # ----------------------------------------------------------
    # CORE HTTP LISTENER
    # ----------------------------------------------------------
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        try:
            tool_name = self._callbacks.getToolName(toolFlag)
            is_enabled = any(enabled_tool.lower() in tool_name.lower() for enabled_tool in self.enabled_tools)
            
            if not is_enabled:
                return

            if messageIsRequest:
                self._inject_tokens(messageInfo)
            else:
                self._check_and_refresh(messageInfo)
                
        except java.lang.Throwable as e:
            self._stderr.println("[-] Critical Java Error: " + str(e))
        except Exception as e:
            self._stderr.println("[-] Python Error: " + str(e))

    # ----------------------------------------------------------
    # INJECT TOKENS & REMOVE OSTOKEN
    # ----------------------------------------------------------
    def _inject_tokens(self, messageInfo):
        request = messageInfo.getRequest()
        if not request: return

        # TIME-BASED PROACTIVE REFRESH (Prevents 401s before they happen)
        if self._jwt_token and (time.time() - self.token_fetch_time > self.max_token_age * 60):
            with self._refresh_lock:
                if time.time() - self.token_fetch_time > self.max_token_age * 60:
                    self._refresh_tokens()
                    self.token_fetch_time = time.time()

        req_info = self._helpers.analyzeRequest(request)
        headers = list(req_info.getHeaders())
        body = request[req_info.getBodyOffset():]

        auth_idx = -1
        cookie_idx = -1
        ostoken_indices = []

        for i, hdr in enumerate(headers):
            lower_hdr = hdr.lower()
            if lower_hdr.startswith("authorization:"):
                auth_idx = i
            elif lower_hdr.startswith("cookie:"):
                cookie_idx = i
            elif lower_hdr.startswith("ostoken:"):
                ostoken_indices.append(i) # MARK FOR DELETION

        modified = False

        # REMOVE OSTOKEN HEADERS
        for idx in reversed(ostoken_indices):
            headers.pop(idx)
            modified = True

        # Inject JWT
        if self._jwt_token:
            clean_token = self._jwt_token.split(' ')[-1]
            auth_header = "Authorization: Bearer " + clean_token
            if auth_idx != -1:
                if headers[auth_idx] != auth_header:
                    headers[auth_idx] = auth_header
                    modified = True
            else:
                headers.insert(1, auth_header)
                modified = True

        # Inject JSESSIONID
        if self._jsessionid:
            jsession_cookie = "JSESSIONID=" + self._jsessionid
            if cookie_idx != -1:
                cookie_header = headers[cookie_idx]
                if "JSESSIONID=" in cookie_header.upper():
                    new_cookie = self._re_jsessionid.sub("JSESSIONID=" + self._jsessionid, cookie_header)
                    if new_cookie != cookie_header:
                        headers[cookie_idx] = new_cookie
                        modified = True
                else:
                    headers[cookie_idx] = cookie_header + "; " + jsession_cookie
                    modified = True
            else:
                headers.append("Cookie: " + jsession_cookie)
                modified = True

        if modified:
            new_request = self._helpers.buildHttpMessage(headers, body)
            messageInfo.setRequest(new_request)

    # ----------------------------------------------------------
    # CHECK AND REFRESH (FIXED THUNDERING HERD BUG)
    # ----------------------------------------------------------
    def _check_and_refresh(self, messageInfo):
        response = messageInfo.getResponse()
        if not response: return

        # Prevent infinite retry loops
        req_info = self._helpers.analyzeRequest(messageInfo.getRequest())
        for hdr in req_info.getHeaders():
            if hdr.lower().startswith("x-sso-retried:"):
                return 

        resp_info = self._helpers.analyzeResponse(response)
        status = resp_info.getStatusCode()
        
        body_str = self._helpers.bytesToString(response[resp_info.getBodyOffset():])
        needs_refresh = (status == 401) or ("Jwt token Expired!" in body_str)

        if needs_refresh:
            with self._refresh_lock:
                current_time = time.time()
                if current_time - self._last_refresh > 5.0:
                    self._stdout.println("[!] Token expired. Refreshing...")
                    if self._refresh_tokens():
                        self.token_fetch_time = current_time
                    self._last_refresh = current_time
            
            # CRITICAL FIX: ALL threads that got a 401 MUST retry, not just the first one.
            # This completely removes the 401 from the scanner logs for concurrent requests.
            self._retry_request(messageInfo)

    def _retry_request(self, messageInfo):
        self._inject_tokens(messageInfo)
        
        # Add X-SSO-Retried header to prevent infinite loops
        request = messageInfo.getRequest()
        req_info = self._helpers.analyzeRequest(request)
        headers = list(req_info.getHeaders())
        body = request[req_info.getBodyOffset():]
        
        headers.append("X-SSO-Retried: 1")
        new_request = self._helpers.buildHttpMessage(headers, body)
        messageInfo.setRequest(new_request)
        
        http_service = messageInfo.getHttpService()
        try:
            new_response = self._callbacks.makeHttpRequest(http_service, new_request)
            if new_response and new_response.getResponse():
                messageInfo.setResponse(new_response.getResponse())
        except java.lang.Throwable as e:
            self._stderr.println("[-] Retry request failed: " + str(e))

    def _refresh_tokens(self):
        try:
            location_url = self._get_sso_location()
            if not location_url: return False

            jsessionid = self._fetch_jsessionid(location_url)
            if not jsessionid: return False
            self._jsessionid = jsessionid

            jwt_token = self._fetch_jwt()
            if not jwt_token: return False
            
            self._jwt_token = jwt_token
            self._stdout.println("[+] Tokens refreshed successfully.")
            return True
        except Exception as e:
            self._stderr.println("[-] Refresh flow failed: " + str(e))
            return False

    # ----------------------------------------------------------
    # SSO FLOW METHODS
    # ----------------------------------------------------------
    def _get_sso_location(self):
        host = self._host(self.sso_url)
        path = self._extract_path(self.sso_url)
        headers = [
            "GET " + path + " HTTP/1.1", "Host: " + host,
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:151.0) Gecko/20100101 Firefox/151.0",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Cookie: " + self.sso_cookies, "Connection: close"
        ]
        response_bytes = self._make_request(self.sso_url, headers)
        if not response_bytes: return None
        resp_info = self._helpers.analyzeResponse(response_bytes)
        if resp_info.getStatusCode() in [301, 302, 303, 307, 308]:
            for hdr in resp_info.getHeaders():
                if hdr.lower().startswith("location:"):
                    return hdr.split(":", 1)[1].strip()
        return None

    def _fetch_jsessionid(self, location_url):
        if location_url.startswith("/"):
            location_url = self._scheme(self.sso_url) + "://" + self._host(self.sso_url) + location_url
        host = self._host(location_url)
        path = self._extract_path(location_url)
        headers = [
            "GET " + path + " HTTP/1.1", "Host: " + host,
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:151.0) Gecko/20100101 Firefox/151.0",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Cookie: " + self.sso_cookies, "Connection: close"
        ]
        response_bytes = self._make_request(location_url, headers)
        if not response_bytes: return None
        resp_info = self._helpers.analyzeResponse(response_bytes)
        if resp_info.getStatusCode() in [301, 302, 303, 307, 308]:
            self._stderr.println("[-] 302 on Location URL - SSO cookies expired.")
            return None
        for hdr in resp_info.getHeaders():
            if "set-cookie" in hdr.lower() and "jsessionid" in hdr.lower():
                match = self._re_jsessionid.search(hdr)
                if match: return match.group(1)
        return None

    def _fetch_jwt(self):
        host = self._host(self.token_url)
        path = self._extract_path(self.token_url)
        headers = [
            "GET " + path + " HTTP/1.1", "Host: " + host,
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:151.0) Gecko/20100101 Firefox/151.0",
            "Accept: application/json, text/plain, */*",
            "Cookie: JSESSIONID=" + self._jsessionid, "Connection: close"
        ]
        response_bytes = self._make_request(self.token_url, headers)
        if not response_bytes: return None
        resp_info = self._helpers.analyzeResponse(response_bytes)
        if resp_info.getStatusCode() in [301, 302, 303, 307, 308]:
            self._stderr.println("[-] 302 on token endpoint. JSESSIONID invalid or SSO cookies expired.")
            return None
        body_str = self._helpers.bytesToString(response_bytes[resp_info.getBodyOffset():])
        try:
            data = json.loads(body_str)
            return data.get("token")
        except Exception:
            return None

    # ----------------------------------------------------------
    # UTILITY HELPERS
    # ----------------------------------------------------------
    def _make_request(self, url, headers, body=None):
        try:
            use_https = url.lower().startswith("https")
            host = self._host(url)
            port = 443 if use_https else 80
            http_svc = self._helpers.buildHttpService(host, port, use_https)
            body_bytes = self._helpers.stringToBytes(body) if body else self._helpers.stringToBytes("")
            req_bytes = self._helpers.buildHttpMessage(headers, body_bytes)
            response = self._callbacks.makeHttpRequest(http_svc, req_bytes)
            return response.getResponse() if response else None
        except java.lang.Throwable as e:
            self._stderr.println("[-] Network error (" + host + "): " + str(e))
            return None
        except Exception as e:
            self._stderr.println("[-] _make_request error: " + str(e))
            return None

    def _host(self, url):
        no_scheme = self._re_scheme.sub('', url)
        return no_scheme.split("/")[0].split("?")[0]

    def _scheme(self, url):
        return "https" if url.lower().startswith("https") else "http"

    def _extract_path(self, url):
        match = self._re_path.match(url)
        if match:
            path = match.group(1)
            return path if path else "/"
        return "/"
