# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener, ITab
from java.io import PrintWriter
from javax.swing import JPanel, JCheckBox, BoxLayout, JLabel, BorderFactory
from java.awt import Component
import threading
import json
import re

class BurpExtender(IBurpExtender, IHttpListener, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        self._stdout    = PrintWriter(callbacks.getStdout(), True)
        self._stderr    = PrintWriter(callbacks.getStderr(), True)

        # =====================================================
        # CONFIGURE THESE VALUES ONLY
        # =====================================================
        self.sso_url = "https://sso.com/sgconnect/oauth2/authorize?scope=openid%20profile&response_type=code&redirect_uri=https://host.com/explorer-wa/&nonce=MTc4MDk4MTM1MTY50A%3D%3D&client_id=XXXXXXXXXXXXXXXX"
        self.sso_cookies = "SGX_tid=XXXXXXXXXXXXXXXXXXXXXXXX; sgx-11=XXXXXXXXXXXXXXXX; OAUTH_REQUEST_ATTRIBUTES=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX; SGX_PRD_authN_sticky_id=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX; amlbcookie=01; 12=XXXXXXXXXXXX"
        self.token_url = "https://host.com/explore-wa/token"
        # =====================================================

        # Thread Safety & Memory Storage
        self._jsessionid = None
        self._jwt_token  = None
        self.refresh_lock = threading.Lock()

        callbacks.setExtensionName("SSO God-Mode Auto Refresher")
        
        # Build the UI Panel
        self._build_ui()
        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)

        self._stdout.println("[+] SSO Refresher Loaded.")
        self._stdout.println("[+] OStoken will be brutally executed on sight.")
        self._stdout.println("[+] Proactive injection enabled. 401s will be intercepted and crushed.")

    # ----------------------------------------------------------
    # UI IMPLEMENTATION (LIGHTWEIGHT SWING)
    # ----------------------------------------------------------
    def getTabCaption(self):
        return "SSO God-Mode"

    def getUiComponent(self):
        return self.ui_panel

    def _build_ui(self):
        self.ui_panel = JPanel()
        self.ui_panel.setLayout(BoxLayout(self.ui_panel, BoxLayout.Y_AXIS))
        self.ui_panel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15))

        lbl = JLabel("<html><h3>Select Burp Tools to apply Token Injection & Auto-Refresh:</h3></html>")
        lbl.setAlignmentX(Component.LEFT_ALIGNMENT)
        self.ui_panel.add(lbl)

        self.tool_boxes = {}
        # Mapping UI names to Burp Tool Flags. Burp AI usually uses Extender/Scanner flags.
        tools = [
            ("Target", self._callbacks.TOOL_TARGET, True),
            ("Intruder", self._callbacks.TOOL_INTRUDER, True),
            ("Extensions", self._callbacks.TOOL_EXTENDER, True),
            ("Scanner", self._callbacks.TOOL_SCANNER, True),
            ("Sequencer", self._callbacks.TOOL_SEQUENCER, True),
            ("Proxy (use with caution)", self._callbacks.TOOL_PROXY, False),
            ("Repeater", self._callbacks.TOOL_REPEATER, True),
            ("Burp AI", self._callbacks.TOOL_EXTENDER, True) 
        ]

        for name, flag, default_state in tools:
            chk = JCheckBox(name)
            chk.setSelected(default_state)
            chk.setAlignmentX(Component.LEFT_ALIGNMENT)
            self.tool_boxes[name] = {'box': chk, 'flag': flag}
            self.ui_panel.add(chk)

    def _is_tool_enabled(self, toolFlag):
        for name, data in self.tool_boxes.items():
            if data['box'].isSelected() and data['flag'] == toolFlag:
                return True
            # Special bypass for Burp AI if running under an unrecognized flag
            if name == "Burp AI" and data['box'].isSelected() and toolFlag not in [4,8,16,32,64,256]:
                return True
        return False

    # ----------------------------------------------------------
    # CORE HTTP PROCESSING
    # ----------------------------------------------------------
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not self._is_tool_enabled(toolFlag):
            return

        try:
            if messageIsRequest:
                self._proactive_inject(messageInfo)
            else:
                self._reactive_refresh(messageInfo)
        except Exception as e:
            self._stderr.println("[-] FATAL in processHttpMessage: " + str(e))

    # ----------------------------------------------------------
    # PROACTIVE INJECTION (NO MORE 401 ON FIRST REQUEST)
    # ----------------------------------------------------------
    def _proactive_inject(self, messageInfo):
        request_bytes = messageInfo.getRequest()
        if not request_bytes: return

        req_info = self._helpers.analyzeRequest(request_bytes)
        headers = list(req_info.getHeaders())
        body_bytes = request_bytes[req_info.getBodyOffset():]

        new_headers = []
        auth_replaced = False
        modified = False

        # Keep the HTTP method line
        new_headers.append(headers[0])

        for hdr in headers[1:]:
            lower_hdr = hdr.lower()

            # NUKE OSTOKEN HEADER FROM EXISTENCE
            if lower_hdr.startswith("ostoken:"):
                modified = True
                continue

            # INJECT JWT
            if lower_hdr.startswith("authorization:"):
                if self._jwt_token:
                    new_headers.append("Authorization: Bearer " + self._jwt_token)
                    auth_replaced = True
                    modified = True
                else:
                    new_headers.append(hdr)
                continue

            # INJECT JSESSIONID
            if lower_hdr.startswith("cookie:"):
                if self._jsessionid:
                    if "jsessionid=" in lower_hdr:
                        # Fast Regex to replace existing JSESSIONID without breaking other cookies
                        hdr = re.sub(r'(?i)(JSESSIONID=)[^;\s]+', r'\g<1>' + self._jsessionid, hdr)
                    else:
                        hdr = hdr + "; JSESSIONID=" + self._jsessionid
                    modified = True
                new_headers.append(hdr)
                continue

            new_headers.append(hdr)

        # ADD AUTHORIZATION IF MISSING ENTIRELY
        if not auth_replaced and self._jwt_token:
            new_headers.append("Authorization: Bearer " + self._jwt_token)
            modified = True

        if modified:
            new_request = self._helpers.buildHttpMessage(new_headers, body_bytes)
            messageInfo.setRequest(new_request)

    # ----------------------------------------------------------
    # REACTIVE REFRESH (INTERCEPTS 401s AND FIXES THEM INVISIBLY)
    # ----------------------------------------------------------
    def _reactive_refresh(self, messageInfo):
        response_bytes = messageInfo.getResponse()
        if not response_bytes: return

        resp_info = self._helpers.analyzeResponse(response_bytes)
        status = resp_info.getStatusCode()
        
        # Don't waste CPU parsing body if it's not a 401 or close to it
        if status not in [401, 403]:
            return

        body_offset = resp_info.getBodyOffset()
        resp_body = self._helpers.bytesToString(response_bytes[body_offset:])

        if "Jwt token Expired!" not in resp_body and status != 401:
            return

        self._stdout.println("[!] 401 Detected. HALTING THREADS AND INITIATING REFRESH.")

        # Extract old token to check if another thread already fixed it
        req_info = self._helpers.analyzeRequest(messageInfo.getRequest())
        old_token = None
        for h in req_info.getHeaders():
            if h.lower().startswith("authorization: bearer "):
                old_token = h.split(" ", 2)[-1].strip()

        # THREAD LOCK: Stop 50 intruder threads from spamming SSO simultaneously
        with self.refresh_lock:
            if self._jwt_token and self._jwt_token != old_token:
                self._stdout.println("[+] Another thread already refreshed the token. Resuming.")
            else:
                success = self._perform_full_auth_flow()
                if not success:
                    self._stderr.println("[-] AUTH FLOW FAILED. Cannot retry request.")
                    return

        # Token is refreshed. Re-issue the EXACT same request.
        # _proactive_inject already runs on the outgoing request via makeHttpRequest!
        self._retry_request(messageInfo)

    # ----------------------------------------------------------
    # RETRY LOGIC (INVISIBLE TO BURP TOOLS)
    # ----------------------------------------------------------
    def _retry_request(self, messageInfo):
        try:
            original_request = messageInfo.getRequest()
            
            # Manually apply new tokens to this specific retry buffer
            req_info = self._helpers.analyzeRequest(original_request)
            headers = list(req_info.getHeaders())
            body_bytes = original_request[req_info.getBodyOffset():]
            
            new_headers = [headers[0]]
            for hdr in headers[1:]:
                lh = hdr.lower()
                if lh.startswith("ostoken:"): continue
                if lh.startswith("authorization:"):
                    new_headers.append("Authorization: Bearer " + self._jwt_token)
                    continue
                if lh.startswith("cookie:") and self._jsessionid:
                    if "jsessionid=" in lh:
                        hdr = re.sub(r'(?i)(JSESSIONID=)[^;\s]+', r'\g<1>' + self._jsessionid, hdr)
                    else:
                        hdr = hdr + "; JSESSIONID=" + self._jsessionid
                    new_headers.append(hdr)
                    continue
                new_headers.append(hdr)

            retry_request = self._helpers.buildHttpMessage(new_headers, body_bytes)
            http_service = messageInfo.getHttpService()
            
            # Fire the request
            new_response = self._callbacks.makeHttpRequest(http_service, retry_request)
            
            # OVERWRITE the 401 response with the new 200 OK so Burp tools never see the failure!
            messageInfo.setRequest(retry_request)
            if new_response.getResponse():
                messageInfo.setResponse(new_response.getResponse())
                self._stdout.println("[+] Request retried successfully and invisible to scanner.")

        except Exception as e:
            self._stderr.println("[-] _retry_request error: " + str(e))

    # ----------------------------------------------------------
    # FULL 3-STEP AUTH FLOW
    # ----------------------------------------------------------
    def _perform_full_auth_flow(self):
        self._stdout.println("[*] Step 1: Fetching Location URL from SSO...")
        location_url = self._get_sso_location()
        if not location_url: return False

        self._stdout.println("[*] Step 2: Fetching JSESSIONID...")
        jsessionid = self._fetch_jsessionid(location_url)
        if not jsessionid: return False
        self._jsessionid = jsessionid

        self._stdout.println("[*] Step 3: Fetching JWT...")
        jwt_token = self._fetch_jwt()
        if not jwt_token: return False
        self._jwt_token = jwt_token

        self._stdout.println("[+] ALL TOKENS REFRESHED AND SAVED TO MEMORY.")
        return True

    def _get_sso_location(self):
        try:
            host = self._host(self.sso_url)
            path = self._extract_path(self.sso_url)

            headers = [
                "GET " + path + " HTTP/1.1",
                "Host: " + host,
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:151.0) Gecko/20100101 Firefox/151.0",
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Cookie: " + self.sso_cookies,
                "Connection: close"
            ]

            response_bytes = self._make_request(self.sso_url, headers)
            if not response_bytes: return None

            resp_info = self._helpers.analyzeResponse(response_bytes)
            for hdr in resp_info.getHeaders():
                if hdr.lower().startswith("location:"):
                    return hdr.split(":", 1)[1].strip()
            self._stderr.println("[-] No Location header found in SSO response.")
            return None
        except Exception as e:
            self._stderr.println("[-] _get_sso_location error: " + str(e))
            return None

    def _fetch_jsessionid(self, location_url):
        try:
            if location_url.startswith("/"):
                location_url = self._scheme(self.sso_url) + "://" + self._host(self.sso_url) + location_url

            headers = [
                "GET " + self._extract_path(location_url) + " HTTP/1.1",
                "Host: " + self._host(location_url),
                "User-Agent: Mozilla/5.0",
                "Cookie: " + self.sso_cookies,
                "Connection: close"
            ]

            response_bytes = self._make_request(location_url, headers)
            if not response_bytes: return None

            resp_info = self._helpers.analyzeResponse(response_bytes)
            if resp_info.getStatusCode() in [301, 302, 303, 307, 308]:
                self._stderr.println("[-] WARNING: Location URL returned 302. Your sso_cookies are likely expired! Update them in the script.")
                return None

            for hdr in resp_info.getHeaders():
                if "set-cookie" in hdr.lower() and "jsessionid" in hdr.lower():
                    match = re.search(r'JSESSIONID=([^;,\s]+)', hdr, re.IGNORECASE)
                    if match: return match.group(1)

            self._stderr.println("[-] JSESSIONID not found in Set-Cookie header.")
            return None
        except Exception as e:
            self._stderr.println("[-] _fetch_jsessionid error: " + str(e))
            return None

    def _fetch_jwt(self):
        try:
            headers = [
                "GET " + self._extract_path(self.token_url) + " HTTP/1.1",
                "Host: " + self._host(self.token_url),
                "User-Agent: Mozilla/5.0",
                "Accept: application/json",
                "Cookie: JSESSIONID=" + self._jsessionid,
                "Connection: close"
            ]

            response_bytes = self._make_request(self.token_url, headers)
            if not response_bytes: return None

            resp_info = self._helpers.analyzeResponse(response_bytes)
            body_offset = resp_info.getBodyOffset()
            resp_body = self._helpers.bytesToString(response_bytes[body_offset:])

            try:
                data = json.loads(resp_body)
                return data.get("token")
            except Exception as e:
                self._stderr.println("[-] JSON parse error on JWT: " + str(e))
                return None
        except Exception as e:
            self._stderr.println("[-] _fetch_jwt error: " + str(e))
            return None

    # ----------------------------------------------------------
    # FAST UTILITY HELPERS
    # ----------------------------------------------------------
    def _make_request(self, url, headers):
        try:
            use_https = url.lower().startswith("https")
            host = self._host(url)
            port = 443 if use_https else 80
            http_svc = self._helpers.buildHttpService(host, port, use_https)
            req_bytes = self._helpers.buildHttpMessage(headers, None)
            response = self._callbacks.makeHttpRequest(http_svc, req_bytes)
            return response.getResponse() if response else None
        except Exception as e:
            # This catches the UnknownHostException gracefully instead of crashing Burp
            self._stderr.println("[-] Network Error hitting " + str(url) + ": " + str(e))
            return None

    def _host(self, url):
        return re.sub(r'^https?://', '', url).split("/")[0].split("?")[0]

    def _scheme(self, url):
        return "https" if url.lower().startswith("https") else "http"

    def _extract_path(self, url):
        match = re.match(r'^https?://[^/]+(.*)', url)
        return match.group(1) if match and match.group(1) else "/"
