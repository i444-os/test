# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener, ITab, IExtensionStateListener
from java.io import PrintWriter
from javax.swing import (JPanel, JCheckBox, JLabel, JTextField, JTextArea, JButton, JScrollPane, 
                         SwingUtilities, BoxLayout, BorderFactory, JSplitPane)
from java.awt import BorderLayout, GridLayout, FlowLayout, Color, Font
from java.net import URL
import threading
import json
import base64
import time
import re

class BurpExtender(IBurpExtender, IHttpListener, ITab, IExtensionStateListener):
    
    def registerExtenderCallbacks(self, callbacks):
        # I don't mess around. Initialization phase.
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        
        callbacks.setExtensionName("Apex Session Manager (Angry Edition)")
        
        # Core State Variables (Thread-Safe)
        self.lock = threading.RLock()
        self.is_running = False
        self.jwt_token = None
        self.jsessionid = None
        self.token_exp = 0
        
        # Build the UI
        self.build_ui()
        
        # Register listeners
        callbacks.registerHttpListener(self)
        callbacks.registerExtensionStateListener(self)
        callbacks.addSuiteTab(self)
        
        self.log(">>> APEX SESSION MANAGER LOADED. Ready to crush the benchmark. <<<")

    def log(self, message):
        self.stdout.println("[*] " + str(message))

    def getTabCaption(self):
        return "Apex Session"

    def getUiComponent(self):
        return self.main_panel
        
    def extensionUnloaded(self):
        self.is_running = False
        self.log("Extension unloaded. Memory freed. Goodbye.")

    # -------------------------------------------------------------------------
    # UI CONSTRUCTION - Memory efficient, clean layout
    # -------------------------------------------------------------------------
    def build_ui(self):
        self.main_panel = JPanel(BorderLayout(10, 10))
        self.main_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        # TOP PANEL: Status & Control
        top_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.btn_toggle = JButton("START EXTENSION", actionPerformed=self.toggle_extension)
        self.btn_toggle.setBackground(Color(200, 50, 50))
        self.btn_toggle.setForeground(Color.WHITE)
        self.btn_toggle.setFont(Font("Arial", Font.BOLD, 14))
        
        self.lbl_status = JLabel(" Status: STOPPED | Token: NULL")
        self.lbl_status.setFont(Font("Arial", Font.BOLD, 12))
        
        top_panel.add(self.btn_toggle)
        top_panel.add(self.lbl_status)
        self.main_panel.add(top_panel, BorderLayout.NORTH)
        
        # CENTER PANEL: Configuration
        config_panel = JPanel()
        config_panel.setLayout(BoxLayout(config_panel, BoxLayout.Y_AXIS))
        
        # Target Config
        pnl_targets = JPanel(GridLayout(2, 4, 5, 5))
        pnl_targets.setBorder(BorderFactory.createTitledBorder("1. Target Configuration"))
        pnl_targets.add(JLabel("SSO Domain:"))
        self.txt_sso_host = JTextField("sso.com")
        pnl_targets.add(self.txt_sso_host)
        pnl_targets.add(JLabel("SSO Port/HTTPS:"))
        self.txt_sso_port = JTextField("443")
        self.chk_sso_https = JCheckBox("HTTPS", True)
        p1 = JPanel(FlowLayout(FlowLayout.LEFT)); p1.add(self.txt_sso_port); p1.add(self.chk_sso_https); pnl_targets.add(p1)
        
        pnl_targets.add(JLabel("Main Domain:"))
        self.txt_main_host = JTextField("main.com")
        pnl_targets.add(self.txt_main_host)
        pnl_targets.add(JLabel("Main Port/HTTPS:"))
        self.txt_main_port = JTextField("443")
        self.chk_main_https = JCheckBox("HTTPS", True)
        p2 = JPanel(FlowLayout(FlowLayout.LEFT)); p2.add(self.txt_main_port); p2.add(self.chk_main_https); pnl_targets.add(p2)
        config_panel.add(pnl_targets)
        
        # Request Mod Config
        pnl_req_mod = JPanel(GridLayout(2, 2, 5, 5))
        pnl_req_mod.setBorder(BorderFactory.createTitledBorder("2. Header Modifications (Comma Separated)"))
        pnl_req_mod.add(JLabel("Headers to Strip:"))
        self.txt_strip_headers = JTextField("sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest")
        pnl_req_mod.add(self.txt_strip_headers)
        
        pnl_req_mod.add(JLabel("Auth Header Format:"))
        self.txt_auth_format = JTextField("Bearer {}")
        pnl_req_mod.add(self.txt_auth_format)
        config_panel.add(pnl_req_mod)

        # Scopes
        pnl_scope = JPanel(FlowLayout(FlowLayout.LEFT))
        pnl_scope.setBorder(BorderFactory.createTitledBorder("3. Tool Scope Selection"))
        self.chk_target = JCheckBox("Target")
        self.chk_intruder = JCheckBox("Intruder", True)
        self.chk_scanner = JCheckBox("Scanner")
        self.chk_repeater = JCheckBox("Repeater", True)
        self.chk_extensions = JCheckBox("Extensions")
        self.chk_sequencer = JCheckBox("Sequencer")
        self.chk_proxy = JCheckBox("Proxy (Use with caution)")
        
        for chk in [self.chk_target, self.chk_intruder, self.chk_scanner, self.chk_repeater, 
                    self.chk_extensions, self.chk_sequencer, self.chk_proxy]:
            pnl_scope.add(chk)
        config_panel.add(pnl_scope)

        # Base Request Area
        pnl_req1 = JPanel(BorderLayout())
        pnl_req1.setBorder(BorderFactory.createTitledBorder("4. Request 1 (Raw GET to SSO) - Updates Daily Cookies Here"))
        default_req = ("GET /sgconnect/oauth2/authorize?scope=openid+profile&response_type=code&redirect_uri=https%3A%2F%2Fmain.com%2Ftransact-explorer-wa%2F&nonce=MTc4MTAwNzA4MTEyNA%3D%3D&client_id=4f08fd1b-65b9-4a17-a700-ab249c060a05 HTTP/1.1\r\n"
                       "Host: sso.com\r\n"
                       "Connection: keep-alive\r\n"
                       "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                       "Cookie: SGX_tid=13c4f8114520a476220931ab1f7673d3; amlbcookie=01; sgx-l1=YOUR_COOKIE_HERE\r\n\r\n")
        self.txt_req1_raw = JTextArea(default_req, 10, 50)
        self.txt_req1_raw.setFont(Font("Monospaced", Font.PLAIN, 12))
        pnl_req1.add(JScrollPane(self.txt_req1_raw), BorderLayout.CENTER)
        config_panel.add(pnl_req1)
        
        # Log Area
        pnl_logs = JPanel(BorderLayout())
        pnl_logs.setBorder(BorderFactory.createTitledBorder("Live Execution Logs"))
        self.txt_logs = JTextArea(10, 50)
        self.txt_logs.setFont(Font("Monospaced", Font.PLAIN, 12))
        self.txt_logs.setEditable(False)
        pnl_logs.add(JScrollPane(self.txt_logs), BorderLayout.CENTER)

        split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT, config_panel, pnl_logs)
        split_pane.setResizeWeight(0.7)
        self.main_panel.add(split_pane, BorderLayout.CENTER)

    def toggle_extension(self, event):
        self.is_running = not self.is_running
        if self.is_running:
            self.btn_toggle.setText("STOP EXTENSION")
            self.btn_toggle.setBackground(Color(50, 150, 50))
            self.ui_log("Extension STARTED. Intercepting configured tools.")
            threading.Thread(target=self.fetch_new_token).start()
        else:
            self.btn_toggle.setText("START EXTENSION")
            self.btn_toggle.setBackground(Color(200, 50, 50))
            self.ui_log("Extension STOPPED.")

    def ui_log(self, msg):
        self.log(msg)
        def update():
            self.txt_logs.append("[*] " + msg + "\n")
            self.txt_logs.setCaretPosition(self.txt_logs.getDocument().getLength())
            status = "RUNNING" if self.is_running else "STOPPED"
            exp_time = time.strftime('%H:%M:%S', time.localtime(self.token_exp)) if self.token_exp > 0 else "NULL"
            self.lbl_status.setText(" Status: {} | Token Exp: {}".format(status, exp_time))
        SwingUtilities.invokeLater(update)

    def is_tool_enabled(self, toolFlag):
        if toolFlag == self.callbacks.TOOL_TARGET and self.chk_target.isSelected(): return True
        if toolFlag == self.callbacks.TOOL_INTRUDER and self.chk_intruder.isSelected(): return True
        if toolFlag == self.callbacks.TOOL_SCANNER and self.chk_scanner.isSelected(): return True
        if toolFlag == self.callbacks.TOOL_REPEATER and self.chk_repeater.isSelected(): return True
        if toolFlag == self.callbacks.TOOL_EXTENDER and self.chk_extensions.isSelected(): return True
        if toolFlag == self.callbacks.TOOL_SEQUENCER and self.chk_sequencer.isSelected(): return True
        if toolFlag == self.callbacks.TOOL_PROXY and self.chk_proxy.isSelected(): return True
        return False

    # -------------------------------------------------------------------------
    # CORE AUTHENTICATION LOGIC - The 3 Step OAuth Bypass
    # -------------------------------------------------------------------------
    def get_exp_from_jwt(self, token):
        try:
            parts = token.split('.')
            if len(parts) < 2: return 0
            payload = parts[1]
            payload += '=' * (-len(payload) % 4) 
            decoded = base64.urlsafe_b64decode(payload.encode('ascii'))
            data = json.loads(decoded.decode('utf-8'))
            return float(data.get('exp', 0))
        except Exception as e:
            self.ui_log("JWT Decode Error: " + str(e))
            return 0

    def is_token_valid(self):
        return self.jwt_token is not None and self.jsessionid is not None and (self.token_exp - time.time()) > 15

    def make_call(self, host, port, is_https, req_bytes):
        service = self.helpers.buildHttpService(host, int(port), is_https)
        return self.callbacks.makeHttpRequest(service, req_bytes)

    def fetch_new_token(self):
        # DOUBLE CHECKED LOCKING
        if self.is_token_valid():
            return True

        with self.lock:
            if self.is_token_valid():
                return True
                
            self.ui_log("Initiating highly-optimized 3-step OAuth flow...")
            
            sso_host = self.txt_sso_host.getText().strip()
            sso_port = self.txt_sso_port.getText().strip()
            sso_https = self.chk_sso_https.isSelected()
            main_host = self.txt_main_host.getText().strip()
            main_port = self.txt_main_port.getText().strip()
            main_https = self.chk_main_https.isSelected()

            # --- STEP 1 ---
            raw_req1 = self.txt_req1_raw.getText().replace('\r\n', '\n').replace('\n', '\r\n')
            resp1 = self.make_call(sso_host, sso_port, sso_https, self.helpers.stringToBytes(raw_req1))
            if not resp1 or not resp1.getResponse():
                self.ui_log("ERROR: Step 1 failed. No response from SSO.")
                return False

            resp1_info = self.helpers.analyzeResponse(resp1.getResponse())
            location = None
            for h in resp1_info.getHeaders():
                if h.lower().startswith("location:"):
                    location = h.split(":", 1)[1].strip()
                    break
            
            if not location:
                self.ui_log("ERROR: Step 1 failed. No Location header found. Update daily cookie?")
                return False
                
            self.ui_log("Step 1 Success. Extracted Location Redirect.")

            # --- STEP 2 ---
            try:
                url = URL(location)
                path_query = url.getFile()
            except:
                path_query = location

            req2_str = "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n".format(path_query, main_host)
            resp2 = self.make_call(main_host, main_port, main_https, self.helpers.stringToBytes(req2_str))
            if not resp2 or not resp2.getResponse():
                self.ui_log("ERROR: Step 2 failed. No response.")
                return False
                
            resp2_info = self.helpers.analyzeResponse(resp2.getResponse())
            jsessionid = None
            for h in resp2_info.getHeaders():
                if h.lower().startswith("set-cookie:"):
                    c_val = h.split(":", 1)[1].strip()
                    match = re.search(r"JSESSIONID=([^;]+)", c_val)
                    if match:
                        jsessionid = match.group(1)
            
            if not jsessionid:
                self.ui_log("ERROR: Step 2 failed. No JSESSIONID set by server.")
                return False

            self.jsessionid = jsessionid
            self.ui_log("Step 2 Success. Extracted NEW JSESSIONID: " + self.jsessionid)

            # --- STEP 3 ---
            req3_str = ("GET /transact-explorer-wa/token HTTP/1.1\r\n"
                        "Host: {}\r\n"
                        "Cookie: JSESSIONID={}\r\n"
                        "Accept: application/json\r\n"
                        "Connection: close\r\n\r\n").format(main_host, self.jsessionid)
            resp3 = self.make_call(main_host, main_port, main_https, self.helpers.stringToBytes(req3_str))
            
            if not resp3 or not resp3.getResponse():
                self.ui_log("ERROR: Step 3 failed. No response.")
                return False
                
            resp3_info = self.helpers.analyzeResponse(resp3.getResponse())
            body_bytes = resp3.getResponse()[resp3_info.getBodyOffset():]
            body_str = self.helpers.bytesToString(body_bytes)
            
            try:
                data = json.loads(body_str)
                token = data.get("token")
                if token:
                    self.jwt_token = token
                    self.token_exp = self.get_exp_from_jwt(token)
                    self.ui_log("Step 3 Success! JWT Token cached. Expires: " + str(self.token_exp))
                    return True
                else:
                    self.ui_log("ERROR: Step 3 failed. JSON did not contain 'token' key.")
            except Exception as e:
                self.ui_log("ERROR: Step 3 failed. JSON parse error: " + str(e))
            
            return False

    # -------------------------------------------------------------------------
    # REQUEST INTERCEPTION & DEAD SESSION PREDATOR
    # -------------------------------------------------------------------------
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not self.is_running: return
        if not self.is_tool_enabled(toolFlag): return

        req_info = self.helpers.analyzeRequest(messageInfo)
        file_path = req_info.getUrl().getFile()
        
        # DO NOT TOUCH CORE OAUTH FLOW
        if ("/sgconnect/oauth2/authorize" in file_path or 
            "/transact-explorer-wa/token" in file_path or 
            ("code=" in file_path and "session_state=" in file_path)):
            return

        if messageIsRequest:
            if not self.is_token_valid():
                if not self.fetch_new_token():
                    self.log("Bypassing mod. Could not fetch token.")
                    return
            
            headers = list(req_info.getHeaders())
            strip_list = [h.strip().lower() for h in self.txt_strip_headers.getText().split(",") if h.strip()]
            
            new_headers = []
            cookie_found = False
            
            for h in headers:
                name = h.split(":")[0].lower().strip()
                if name in strip_list:
                    continue
                if name == "authorization":
                    continue
                if name == "cookie" and self.jsessionid:
                    cookie_found = True
                    c_val = h.split(":", 1)[1].strip()
                    if "JSESSIONID=" in c_val:
                        c_val = re.sub(r"JSESSIONID=[^;]+", "JSESSIONID=" + self.jsessionid, c_val)
                    else:
                        c_val += "; JSESSIONID=" + self.jsessionid
                    new_headers.append("Cookie: " + c_val)
                    continue

                new_headers.append(h)
                
            auth_format = self.txt_auth_format.getText()
            new_headers.append("Authorization: " + auth_format.format(self.jwt_token))
            
            if not cookie_found and self.jsessionid and self.txt_main_host.getText().strip() in req_info.getUrl().getHost():
                new_headers.append("Cookie: JSESSIONID=" + self.jsessionid)
                
            body_bytes = messageInfo.getRequest()[req_info.getBodyOffset():]
            new_req = self.helpers.buildHttpMessage(new_headers, body_bytes)
            messageInfo.setRequest(new_req)

        else:
            # IT'S A RESPONSE - CATCH 401 OR SSO REDIRECTS (DEAD SESSIONS)
            resp_info = self.helpers.analyzeResponse(messageInfo.getResponse())
            status_code = resp_info.getStatusCode()
            
            is_sso_redirect = False
            if status_code in [301, 302, 303, 307, 308]:
                for h in resp_info.getHeaders():
                    if h.lower().startswith("location:"):
                        loc = h.split(":", 1)[1].strip()
                        # THIS is where the magic happens. We caught the app trying to bounce you.
                        if "/sgconnect/oauth2/authorize" in loc and "redirect_uri=" in loc:
                            is_sso_redirect = True
                            break

            if status_code == 401 or is_sso_redirect:
                headers = list(self.helpers.analyzeRequest(messageInfo.getRequest()).getHeaders())
                retry_count = 0
                for h in headers:
                    if h.lower().startswith("x-angry-retry:"):
                        retry_count = int(h.split(":")[1].strip())
                        
                if retry_count > 0:
                    self.ui_log("Loop Detected! Aborting retry for this specific request to save CPU.")
                    return

                if is_sso_redirect:
                    self.ui_log("SSO REDIRECT CAUGHT (Dead Session)! Intercepting bounce, trashing JSESSIONID...")
                else:
                    self.ui_log("401 UNAUTHORIZED CAUGHT! Invalidating token...")
                
                # TOTAL ANNIHILATION OF OLD STATE
                self.token_exp = 0 
                self.jsessionid = None
                
                # Re-fetch completely
                if self.fetch_new_token():
                    # Reconstruct the failed request, inject the completely new JSESSIONID and Token
                    new_headers = []
                    for h in headers:
                        name = h.split(":")[0].lower().strip()
                        if name == "authorization" or name == "x-angry-retry":
                            continue
                        if name == "cookie" and self.jsessionid:
                            c_val = h.split(":", 1)[1].strip()
                            c_val = re.sub(r"JSESSIONID=[^;]+", "JSESSIONID=" + self.jsessionid, c_val)
                            new_headers.append("Cookie: " + c_val)
                            continue
                        new_headers.append(h)
                        
                    auth_format = self.txt_auth_format.getText()
                    new_headers.append("Authorization: " + auth_format.format(self.jwt_token))
                    new_headers.append("X-Angry-Retry: 1") 
                    
                    orig_req_info = self.helpers.analyzeRequest(messageInfo.getRequest())
                    body_bytes = messageInfo.getRequest()[orig_req_info.getBodyOffset():]
                    new_retry_req = self.helpers.buildHttpMessage(new_headers, body_bytes)
                    
                    # Fire it off. The user will literally never know their session died.
                    new_resp = self.callbacks.makeHttpRequest(messageInfo.getHttpService(), new_retry_req)
                    
                    # Overwrite the Burp history item so you only see the successful execution
                    messageInfo.setRequest(new_retry_req)
                    if new_resp and new_resp.getResponse():
                        messageInfo.setResponse(new_resp.getResponse())
