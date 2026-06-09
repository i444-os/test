# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener
from java.io import PrintWriter
import json
import re
import threading
import time
import base64
import java.lang

class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        callbacks.setExtensionName("SSO Auto Refresher & Injector")
        callbacks.registerHttpListener(self)

        # =====================================================
        # 1. SSO CONFIGURATION
        # =====================================================
        
        # Full SSO URL with query params
        self.sso_url = "https://sso.com/sgconnect/oauth2/authorize?scope=openid%20profile&response_type=code&redirect_uri=https://host.com/explorer-wa/&nonce=MTc4MDk4MTM1MTY50A%3D%3D&client_id=XXXXXXXXXXXXXXXX"

        # SSO cookies
        self.sso_cookies = "SGX_tid=XXXXXXXXXXXXXXXXXXXXXXXX; sgx-11=XXXXXXXXXXXXXXXX; OAUTH_REQUEST_ATTRIBUTES=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX; SGX_PRD_authN_sticky_id=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX; amlbcookie=01; 12=XXXXXXXXXXXX"

        # Token endpoint
        self.token_url = "https://host.com/explore-wa/token"

        # =====================================================
        # 2. INJECTION SCOPE & TOOL FILTERING (YOUR REQUESTED OPTIONS)
        # =====================================================
        
        # ONLY inject tokens if the request host contains any of these strings.
        # Leave empty [] to inject into ALL requests regardless of domain.
        self.target_domains = ["host.com", "api.target.com"]

        # ONLY process requests originating from these Burp tools.
        # Comment out tools you DO NOT want to intercept (e.g., TOOL_PROXY).
        self.allowed_tools = [
            callbacks.TOOL_SCANNER,
            callbacks.TOOL_INTRUDER,
            callbacks.TOOL_REPEATER,
            callbacks.TOOL_PROXY,
            callbacks.TOOL_SPIDER,
            callbacks.TOOL_SEQUENCER,
            callbacks.TOOL_TARGET
        ]

        # =====================================================

        self._jsessionid = None
        self._jwt_token = None

        self._refresh_lock = threading.Lock()
        self._last_refresh = 0.0

        # Pre-compile regex
        self._re_jsessionid = re.compile(r'JSESSIONID=([^;,\s]+)', re.IGNORECASE)
        self._re_scheme = re.compile(r'^https?://')
        self._re_path = re.compile(r'^https?://[^/]+(.*)')

        if "sso.com" in self.sso_url or "host.com" in self.token_url:
            self._stderr.println("!!! WARNING: Placeholder URLs detected. Update sso_url and token_url !!!")

        self._stdout.println("[+] SSO Auto Refresher & Injector loaded successfully.")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # 1. Filter by Burp Tool
        if toolFlag not in self.allowed_tools:
            return

        # 2. Filter by Domain Scope
        try:
            req_info = self._helpers.analyzeRequest(messageInfo)
            url = req_info.getUrl()
            host = url.getHost()

            if self.target_domains:
                in_scope = any(domain in host for domain in self.target_domains)
                if not in_scope:
                    return
        except Exception:
            return # Fail open if we can't parse URL

        try:
            if messageIsRequest:
                self._inject_tokens(messageInfo)
            else:
                self._check_and_refresh(messageInfo)
        except java.lang.Throwable as e:
            # Catches fatal Java errors that would otherwise kill the Burp thread
            self._stderr.println("[-] Critical Java Error: " + str(e))
        except Exception as e:
            self._stderr.println("[-] Python Error: " + str(e))

    # ----------------------------------------------------------
    # INJECT TOKENS (Runs on outgoing requests)
    # ----------------------------------------------------------
    def _inject_tokens(self, messageInfo):
        request = messageInfo.getRequest()
        if not request: return

        # Proactive refresh check
        if self._jwt_token and self._is_jwt_expired(self._jwt_token):
            with self._refresh_lock:
                if self._jwt_token and self._is_jwt_expired(self._jwt_token):
                    self._refresh_tokens() # Attempt refresh, if it fails, we just use the old token

        req_info = self._helpers.analyzeRequest(request)
        headers = list(req_info.getHeaders())
        body = request[req_info.getBodyOffset():]

        auth_idx = -1
        cookie_idx = -1

        for i, hdr in enumerate(headers):
            lower_hdr = hdr.lower()
            if lower_hdr.startswith("authorization:"):
                auth_idx = i
            elif lower_hdr.startswith("cookie:"):
                cookie_idx = i

        modified = False

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
    # PROACTIVE JWT EXPIRATION CHECK (Jython Safe)
    # ----------------------------------------------------------
    def _is_jwt_expired(self, jwt_token, buffer_seconds=60):
        try:
            token = jwt_token.split(' ')[-1]
            parts = token.split('.')
            if len(parts) < 2: return False # Don't force refresh if format is weird

            payload = str(parts[1])
            # Fix Jython base64 url-safe decoding manually
            payload = payload.replace('-', '+').replace('_', '/')
            padding = len(payload) % 4
            if padding:
                payload += '=' * (4 - padding)

            decoded_bytes = base64.b64decode(payload)
            payload_json = json.loads(decoded_bytes)

            exp = payload_json.get('exp')
            if exp and time.time() >= float(exp) - buffer_seconds:
                return True
            return False
        except Exception:
            # If decode fails, assume NOT expired to prevent infinite SSO loops
            return False

    # ----------------------------------------------------------
    # CHECK AND REFRESH (Runs on incoming responses)
    # ----------------------------------------------------------
    def _check_and_refresh(self, messageInfo):
        response = messageInfo.getResponse()
        if not response: return

        resp_info = self._helpers.analyzeResponse(response)
        status = resp_info.getStatusCode()
        
        # Use bytesToString for Jython safety instead of raw byte array slicing
        body_str = self._helpers.bytesToString(response[resp_info.getBodyOffset():])
        needs_refresh = (status == 401) or ("Jwt token Expired!" in body_str)

        if needs_refresh:
            with self._refresh_lock:
                current_time = time.time()
                if current_time - self._last_refresh < 5.0:
                    return # Already refreshed recently, don't spam
                
                if self._refresh_tokens():
                    self._last_refresh = current_time
                    self._retry_request(messageInfo)

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

    def _retry_request(self, messageInfo):
        self._inject_tokens(messageInfo)
        http_service = messageInfo.getHttpService()
        try:
            new_response = self._callbacks.makeHttpRequest(http_service, messageInfo.getRequest())
            if new_response and new_response.getResponse():
                messageInfo.setResponse(new_response.getResponse())
        except java.lang.Throwable as e:
            self._stderr.println("[-] Retry request failed: " + str(e))

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
    # UTILITY HELPERS (Java Exception Safe)
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
            # Catches UnknownHostException, ConnectException, etc. without killing the thread
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
