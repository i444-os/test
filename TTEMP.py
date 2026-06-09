# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener
from java.io import PrintWriter
import json
import re
import threading
import time
import base64

class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        callbacks.setExtensionName("SSO Auto Refresher & Injector")
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

        self._jsessionid = None
        self._jwt_token = None
        
        # Thread safety lock & timestamp to prevent concurrent refresh loops
        self._refresh_lock = threading.Lock()
        self._last_refresh = 0.0

        # Pre-compile regex patterns
        self._re_jsessionid = re.compile(r'JSESSIONID=([^;,\s]+)', re.IGNORECASE)
        self._re_scheme = re.compile(r'^https?://')
        self._re_path = re.compile(r'^https?://[^/]+(.*)')

        self._stdout.println("[+] SSO Auto Refresher & Injector loaded successfully.")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Ignore Extender tool to prevent infinite loops and process our own SSO requests
        if toolFlag == self._callbacks.TOOL_EXTENDER:
            return

        try:
            if messageIsRequest:
                self._inject_tokens(messageInfo)
            else:
                self._check_and_refresh(messageInfo)
        except Exception as e:
            self._stderr.println("[-] Error in processHttpMessage: " + str(e))

    # ----------------------------------------------------------
    # INJECT TOKENS (Runs on every outgoing request)
    # ----------------------------------------------------------
    def _inject_tokens(self, messageInfo):
        # Proactively check if JWT is expired before injecting to prevent scanner misses
        if self._jwt_token and self._is_jwt_expired(self._jwt_token):
            with self._refresh_lock:
                # Double check after acquiring lock to prevent thundering herd
                if self._jwt_token and self._is_jwt_expired(self._jwt_token):
                    self._stdout.println("[*] JWT proactively detected as expired. Refreshing before request...")
                    if not self._refresh_tokens():
                        self._stderr.println("[-] Proactive refresh failed. Using old token.")

        request = messageInfo.getRequest()
        req_info = self._helpers.analyzeRequest(request)
        headers = list(req_info.getHeaders())
        body = request[req_info.getBodyOffset():]

        auth_idx = -1
        cookie_idx = -1
        
        # Locate existing Authorization and Cookie headers
        for i, hdr in enumerate(headers):
            lower_hdr = hdr.lower()
            if lower_hdr.startswith("authorization:"):
                auth_idx = i
            elif lower_hdr.startswith("cookie:"):
                cookie_idx = i

        modified = False
        
        # Inject or replace JWT Token
        if self._jwt_token:
            # Ensure we don't end up with "Bearer Bearer ey..."
            clean_token = self._jwt_token.split(' ')[-1] if ' ' in self._jwt_token else self._jwt_token
            auth_header = "Authorization: Bearer " + clean_token
            if auth_idx != -1:
                if headers[auth_idx] != auth_header:
                    headers[auth_idx] = auth_header
                    modified = True
            else:
                headers.insert(1, auth_header) # Insert immediately after the GET path
                modified = True

        # Inject or replace JSESSIONID inside the Cookie header
        if self._jsessionid:
            jsession_cookie = "JSESSIONID=" + self._jsessionid
            if cookie_idx != -1:
                cookie_header = headers[cookie_idx]
                if "JSESSIONID=" in cookie_header.upper():
                    # Regex replacement for existing JSESSIONID
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

        # Only rebuild the message if changes were actually made
        if modified:
            new_request = self._helpers.buildHttpMessage(headers, body)
            messageInfo.setRequest(new_request)

    # ----------------------------------------------------------
    # PROACTIVE JWT EXPIRATION CHECK
    # ----------------------------------------------------------
    def _is_jwt_expired(self, jwt_token, buffer_seconds=60):
        try:
            # JWT might be "Bearer ey..." or just "ey..."
            token = jwt_token.split(' ')[-1] 
            parts = token.split('.')
            if len(parts) < 2:
                return True # Invalid JWT format
                
            payload = parts[1]
            # Add base64 padding if necessary
            rem = len(payload) % 4
            if rem > 0:
                payload += '=' * (4 - rem)
                
            decoded_bytes = base64.urlsafe_b64decode(payload)
            payload_json = json.loads(decoded_bytes)
            
            # Check 'exp' claim (seconds since epoch)
            exp = payload_json.get('exp')
            if exp:
                if time.time() >= float(exp) - buffer_seconds:
                    return True
            
            return False
        except Exception as e:
            self._stderr.println("[-] JWT decode error: " + str(e))
            return True # Force refresh if we can't decode

    # ----------------------------------------------------------
    # CHECK AND REFRESH (Runs on every incoming response)
    # ----------------------------------------------------------
    def _check_and_refresh(self, messageInfo):
        response = messageInfo.getResponse()
        if not response:
            return

        resp_info = self._helpers.analyzeResponse(response)
        status = resp_info.getStatusCode()
        
        needs_refresh = False
        
        # Check for 401 or specific expiration string
        if status == 401:
            needs_refresh = True
        else:
            body_offset = resp_info.getBodyOffset()
            # Fast byte-level search instead of stringifying the entire body
            if b"Jwt token Expired!" in response[body_offset:]:
                needs_refresh = True

        if needs_refresh:
            with self._refresh_lock:
                current_time = time.time()
                # Prevent multiple threads from hammering the SSO endpoint simultaneously
                if current_time - self._last_refresh < 5.0:
                    self._retry_request(messageInfo)
                    return
                    
                self._stdout.println("[!] Token expired or 401 detected in response. Refreshing...")
                if self._refresh_tokens():
                    self._last_refresh = current_time
                    self._retry_request(messageInfo)

    def _refresh_tokens(self):
        location_url = self._get_sso_location()
        if not location_url:
            self._stderr.println("[-] Failed Step 1: SSO Location")
            return False

        jsessionid = self._fetch_jsessionid(location_url)
        if not jsessionid:
            self._stderr.println("[-] Failed Step 2: JSESSIONID")
            return False
            
        self._jsessionid = jsessionid

        jwt_token = self._fetch_jwt()
        if not jwt_token:
            self._stderr.println("[-] Failed Step 3: JWT")
            return False
            
        self._jwt_token = jwt_token
        self._stdout.println("[+] Tokens refreshed successfully.")
        return True

    def _retry_request(self, messageInfo):
        # Re-inject fresh tokens into the original request and resend
        self._inject_tokens(messageInfo)
        http_service = messageInfo.getHttpService()
        new_response = self._callbacks.makeHttpRequest(http_service, messageInfo.getRequest())
        
        if new_response and new_response.getResponse():
            messageInfo.setResponse(new_response.getResponse())
            self._stdout.println("[+] Request retried successfully.")

    # ----------------------------------------------------------
    # SSO FLOW METHODS
    # ----------------------------------------------------------
    def _get_sso_location(self):
        try:
            host = self._host(self.sso_url)
            path = self._extract_path(self.sso_url)

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

            response_bytes = self._make_request(self.sso_url, headers)
            if not response_bytes:
                return None

            resp_info = self._helpers.analyzeResponse(response_bytes)
            status = resp_info.getStatusCode()

            if status in [301, 302, 303, 307, 308]:
                for hdr in resp_info.getHeaders():
                    if hdr.lower().startswith("location:"):
                        return hdr.split(":", 1)[1].strip()
            return None
        except Exception as e:
            self._stderr.println("[-] _get_sso_location error: " + str(e))
            return None

    def _fetch_jsessionid(self, location_url):
        try:
            if location_url.startswith("/"):
                location_url = self._scheme(self.sso_url) + "://" + self._host(self.sso_url) + location_url

            host = self._host(location_url)
            path = self._extract_path(location_url)

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

            response_bytes = self._make_request(location_url, headers)
            if not response_bytes:
                return None

            resp_info = self._helpers.analyzeResponse(response_bytes)
            if resp_info.getStatusCode() in [301, 302, 303, 307, 308]:
                self._stderr.println("[-] 302 on Location URL - SSO cookies expired.")
                return None

            for hdr in resp_info.getHeaders():
                if "set-cookie" in hdr.lower() and "jsessionid" in hdr.lower():
                    match = self._re_jsessionid.search(hdr)
                    if match:
                        return match.group(1)
            return None
        except Exception as e:
            self._stderr.println("[-] _fetch_jsessionid error: " + str(e))
            return None

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

            response_bytes = self._make_request(self.token_url, headers)
            if not response_bytes:
                return None

            resp_info = self._helpers.analyzeResponse(response_bytes)
            status = resp_info.getStatusCode()
            
            if status in [301, 302, 303, 307, 308]:
                self._stderr.println("[-] 302 on token endpoint. JSESSIONID invalid or SSO cookies expired. Please update sso_cookies.")
                return None

            body_offset = resp_info.getBodyOffset()
            resp_body = self._helpers.bytesToString(response_bytes[body_offset:])

            try:
                data = json.loads(resp_body)
                token = data.get("token")
                if token:
                    return token
                self._stderr.println("[-] Key 'token' not found in response.")
                return None
            except Exception as e:
                self._stderr.println("[-] JSON parse error: " + str(e))
                return None
        except Exception as e:
            self._stderr.println("[-] _fetch_jwt error: " + str(e))
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
            # Use empty string byte array instead of None to prevent Jython type mapping issues
            body_bytes = self._helpers.stringToBytes(body) if body else self._helpers.stringToBytes("")
            req_bytes = self._helpers.buildHttpMessage(headers, body_bytes)
            response = self._callbacks.makeHttpRequest(http_svc, req_bytes)
            return response.getResponse() if response else None
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
