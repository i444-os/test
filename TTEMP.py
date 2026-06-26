# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener, ITab
from java.io import PrintWriter
from java.lang import Runnable, Thread
from javax.swing import (
    JPanel, JLabel, JTextField, JButton, JCheckBox, JTextArea,
    JScrollPane, BoxLayout, BorderFactory, SwingUtilities, Timer
)
from java.awt import BorderLayout, FlowLayout, GridLayout, Dimension, Color
from java.awt.event import ActionListener
import json
import re
import time
import base64

# Burp tool flag constants (same values as IBurpExtenderCallbacks.TOOL_*)
# These tell us WHICH Burp tool generated the HTTP message we're inspecting.
TOOL_PROXY     = 1     # HTTP traffic passing through the Proxy tab
TOOL_REPEATER  = 2     # Manual single-request testing in Repeater
TOOL_INTRUDER  = 4     # Automated attack payloads in Intruder
TOOL_SCANNER   = 8     # Active/passive vulnerability scanner
TOOL_SEQUENCER = 16    # Session token analysis
TOOL_DECODER   = 32    # Decode/encode utility (no HTTP traffic)
TOOL_COMPARER  = 64    # Response comparison utility (no HTTP traffic)
TOOL_EXTENDER  = 128   # Other extensions (rarely produces traffic)
TOOL_TARGET    = 256   # Target tab site map requests
TOOL_SPIDER    = 4096  # Spider crawler
TOOL_SUIT      = 8192  # Suite-wide

# Human-readable names for logging
TOOL_NAMES = {
    TOOL_PROXY:     "Proxy",
    TOOL_REPEATER:  "Repeater",
    TOOL_INTRUDER:  "Intruder",
    TOOL_SCANNER:   "Scanner",
    TOOL_SEQUENCER: "Sequencer",
    TOOL_DECODER:   "Decoder",
    TOOL_COMPARER:  "Comparer",
    TOOL_EXTENDER:  "Extender",
    TOOL_TARGET:    "Target",
    TOOL_SPIDER:    "Spider",
    TOOL_SUIT:      "Suite",
}

class BurpExtender(IBurpExtender, IHttpListener, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        self._stdout    = PrintWriter(callbacks.getStdout(), True)
        self._stderr    = PrintWriter(callbacks.getStderr(), True)

        callbacks.setExtensionName("SSO JSESSIONID JWT Auto Refresher + License Manager")
        callbacks.registerHttpListener(self)
        # NOTE: do NOT call addSuiteTab here. It must be called AFTER
        # _build_ui() has set self._main_panel, otherwise Burp's
        # immediate call to getUiComponent() will throw
        # "AttributeError: 'BurpExtender' object has no attribute '_main_panel'".

        # =====================================================
        # CONFIGURE THESE VALUES ONLY
        # =====================================================
        #
        # REPLACEMENT CHECKLIST — go through this before loading:
        #
        #   [ ]  1. sso_url              — paste your real SSO authorize URL
        #   [ ]  2. sso_cookies          — paste your real SSO cookies (refresh daily)
        #   [ ]  3. token_url            — paste your real token endpoint
        #   [ ]  4. logout_url           — usually OK as-is, verify host
        #   [ ]  5. current_scan_user    — REPLACE with the userId YOU scan as
        #   [ ]  6. logout_target_userids — REPLACE list with stale userIds to free
        #   [ ]  7. logout_default_company   — verify against your Burp capture
        #   [ ]  8. logout_default_username  — verify against your Burp capture
        #   [ ]  9. logout_noos_1 / noos_2    — verify against your Burp capture
        #   [ ] 10. logout_referer / origin   — verify against your Burp capture
        #   [ ] 11. license_exhausted_markers — verify against real "license full" response
        #   [ ] 12. enabled_tools        — choose which Burp tabs trigger the extension
        #
        # Values marked  <<  REPLACE_ME  >>  MUST be edited before use.
        # Values marked  [verify]        came from your Burp capture and may already be correct,
        #                                  but confirm they match your environment.
        # =====================================================


        # ---- 12. ENABLED BURP TOOLS --------------------------------------
        # Which Burp tabs should the extension act on?
        #
        # IMPORTANT: This controls WHERE the extension listens. If you
        # leave this empty or include the wrong tools, the extension will
        # either do nothing or fire on traffic you didn't intend.
        #
        # Recommended default: Scanner + Intruder + Repeater
        #   - Scanner   : long-running scans need auto-recovery the most
        #   - Intruder  : attacks need auto-recovery so payloads don't fail
        #   - Repeater  : useful when you're manually testing
        #
        # NOT recommended:
        #   - Proxy     : every browser request would trigger inspection.
        #                 Spurious logout/refresh on unrelated responses.
        #   - Spider    : high-volume crawler traffic; same problem as Proxy.
        #   - Target    : usually only used for site-map browsing.
        #
        # To enable a tool, add its name (string) to the set below.
        # Valid names: "Proxy", "Repeater", "Intruder", "Scanner",
        #              "Sequencer", "Decoder", "Comparer", "Extender",
        #              "Target", "Spider", "Suite"
        self.enabled_tools = {
            "Scanner",   # auto-recovery for active scans
            "Intruder",  # auto-recovery for attacks
            "Repeater",  # auto-recovery for manual testing
        }


        # ---- 1. SSO URL ----------------------------------------------------
        # <<  REPLACE_ME  >>  Paste your real SSO authorize URL (the one that
        # issues the 302 to the redirect_uri). Keep the full query string.
        self.sso_url = "<<  REPLACE_ME: full SSO authorize URL with query params  >>"


        # ---- 2. SSO COOKIES -----------------------------------------------
        # <<  REPLACE_ME  >>  Paste your real SSO cookies. Update these daily
        # (or whenever Step 1/2 starts returning 302 instead of 200).
        # Format: "name1=val1; name2=val2; ..."
        self.sso_cookies = "<<  REPLACE_ME: SSO cookies like SGX_tid=...; sgx-11=...; ...  >>"


        # ---- 3. TOKEN ENDPOINT --------------------------------------------
        # <<  REPLACE_ME  >>  The endpoint that returns the JWT given a valid
        # JSESSIONID cookie. Usually ends in /token.
        self.token_url = "<<  REPLACE_ME: https://your-host/.../token  >>"


        # =====================================================
        # LOGOUT / LICENSE MANAGEMENT CONFIG
        # =====================================================

        # ---- 4. LOGOUT ENDPOINT -------------------------------------------
        # [verify]  Came from your Burp capture. Usually fine as-is.
        # Replace the host only if your environment differs.
        self.logout_url = "https://api.main.com/tb-server/api/v1.0.0/browser/logoffRequests"


        # ---- 5. CURRENT SCAN USER (PROTECTED) ----------------------------
        # <<  REPLACE_ME  >>  The userId you are CURRENTLY scanning as.
        #
        # WHY THIS MATTERS:
        #   - This user will NEVER be logged out by the auto-license-free logic.
        #   - If you put the wrong value here, the extension may log YOU out
        #     and kill your active scan session.
        #   - This value should match the userId inside the JWT's 'sub' claim,
        #     OR the userId your scan traffic uses for Defaultusername.
        #
        # How to find it: open a real scan request in Burp, look at the
        # 'Defaultusername' header OR decode your JWT payload and read 'sub'.
        self.current_scan_user = "<<  REPLACE_ME: userId you scan as, e.g. BAS1009929044  >>"


        # ---- 6. LOGOUT TARGET USERIDS ------------------------------------
        # <<  REPLACE_ME  >>  List of userIds whose stale sessions can be freed.
        # These are typically:
        #   - Your own userId from PREVIOUS days (zombie sessions still holding licenses)
        #   - Other users' userIds who are no longer active but still hold a license
        #
        # The extension cycles through this list ONE AT A TIME each time it
        # needs to free a license. If the first logout succeeds, it stops.
        #
        # CRITICAL RULES:
        #   - Do NOT include self.current_scan_user here (it's auto-skipped,
        #     but better to not list it at all to avoid confusion).
        #   - Each entry must be a real userId (e.g. "BAS1009929045").
        #   - If this list is EMPTY, auto-license-free CANNOT work — you'll
        #     see "No logout target userIds configured" in stderr.
        #
        # Uncomment and replace the example entries below:
        self.logout_target_userids = [
            # "<<  REPLACE_ME: stale userId 1  >>",
            # "<<  REPLACE_ME: stale userId 2  >>",
            # "<<  REPLACE_ME: stale userId 3  >>",
        ]


        # ---- 7-10. LOGOUT REQUEST HEADERS --------------------------------
        # [verify]  These came from your Burp capture of the logoffRequests
        # POST. They should already be correct, but open the capture in Burp
        # and confirm each value matches your environment. If your scan uses
        # a different company or username, update accordingly.
        self.logout_default_company  = "BE0010001"              # [verify] Defaultcompany header
        self.logout_default_username = "SHOU1009929044"         # [verify] Defaultusername header
        self.logout_noos_1           = "213541985925578.03:7"   # [verify] first Noos header
        self.logout_noos_2           = "CSAM-CHECKER-BRU"       # [verify] second Noos header
        self.logout_referer          = "https://main.com/"      # [verify] Referer header
        self.logout_origin           = "https://main.com"       # [verify] Origin header


        # ---- 11. LICENSE EXHAUSTION MARKERS ------------------------------
        # [verify]  These are the strings the extension looks for in the
        # RESPONSE BODY to decide "all licenses are occupied".
        #
        # The current list is a generic guess. For reliable detection, open
        # a real "license full" response in Burp, copy the EXACT text from
        # the body, and paste the unique phrases here.
        #
        # Rules:
        #   - Matching is case-insensitive (substring match).
        #   - The word "license" alone only triggers on 4xx responses, to
        #     avoid false positives in normal responses.
        #   - Status codes 429 and 503 always trigger (no body match needed).
        self.license_exhausted_markers = [
            "license",
            "all licenses",
            "occupied",
            "maximum concurrent",
            "no license available",
            "session limit",
            "concurrent session",
        ]


        # ---- COOLDOWN -----------------------------------------------------
        # Seconds to wait between logout attempts. Prevents hammering the
        # logout endpoint when many requests fail at once. Tunable.
        self.logout_cooldown_seconds = 15
        self._last_logout_time = 0


        # =====================================================
        # SESSION CACHING CONFIG (advanced — usually no changes needed)
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

        # Precompute the integer tool-flag mask from the enabled_tools set.
        # This converts human-readable names like "Scanner" into the
        # integer bit flags Burp passes via toolFlag.
        name_to_flag = {
            "Proxy": TOOL_PROXY, "Repeater": TOOL_REPEATER, "Intruder": TOOL_INTRUDER,
            "Scanner": TOOL_SCANNER, "Sequencer": TOOL_SEQUENCER, "Decoder": TOOL_DECODER,
            "Comparer": TOOL_COMPARER, "Extender": TOOL_EXTENDER, "Target": TOOL_TARGET,
            "Spider": TOOL_SPIDER, "Suite": TOOL_SUIT,
        }
        self._enabled_tool_flags = set()
        for name in self.enabled_tools:
            flag = name_to_flag.get(name)
            if flag is not None:
                self._enabled_tool_flags.add(flag)
            else:
                self._stderr.println("WARNING: unknown tool name in enabled_tools: " + name)

        # ---- LOAD-TIME VALIDATION ----------------------------------------
        # Fail fast at load time if any required placeholder was left
        # un-replaced. This avoids confusing runtime errors later.
        missing = []
        if "REPLACE_ME" in self.sso_url:               missing.append("sso_url")
        if "REPLACE_ME" in self.sso_cookies:           missing.append("sso_cookies")
        if "REPLACE_ME" in self.token_url:             missing.append("token_url")
        if "REPLACE_ME" in self.current_scan_user:     missing.append("current_scan_user")
        if not self.logout_target_userids:             missing.append("logout_target_userids (cannot be empty)")

        if missing:
            self._stderr.println("====================================================")
            self._stderr.println("CONFIGURATION INCOMPLETE — extension will NOT work.")
            self._stderr.println("Missing / not replaced:")
            for m in missing:
                self._stderr.println("   - " + m)
            self._stderr.println("Edit the CONFIGURE section at the top of the file and reload.")
            self._stderr.println("====================================================")
        else:
            self._stdout.println("SSO JSESSIONID JWT Refresher + License Manager loaded successfully")
            self._stdout.println("Current scan user (protected from logout): " + self.current_scan_user)
            self._stdout.println("Logout target userIds configured: " + str(len(self.logout_target_userids)))
            # Show which Burp tools the extension will act on, so you can
            # verify the scope at load time. If a tool you expected is
            # missing, edit self.enabled_tools at the top of the file.
            active = [TOOL_NAMES.get(f, "Unknown(" + str(f) + ")") for f in self._enabled_tool_flags]
            self._stdout.println("Active in Burp tools: " + (", ".join(active) if active else "(none — extension will do nothing)"))
            if not self._enabled_tool_flags:
                self._stderr.println("WARNING: enabled_tools is empty — extension will never trigger.")
                self._stderr.println("         Add tool names like 'Scanner', 'Intruder', 'Repeater' to self.enabled_tools.")

        # UI / runtime state for the status panel and activity log
        self._last_refresh_time = 0
        self._last_logout_user   = None
        self._last_logout_time_str = "never"
        self._ui_log_buffer      = []
        self._ui_log_max         = 200  # keep last N lines in the log area

        # Build the UI tab and start the live status updater (2s tick).
        # Both are safe to call here — registerExtenderCallbacks runs once.
        self._build_ui()
        self._start_status_timer()

        # CRITICAL ORDERING: addSuiteTab must be called AFTER _build_ui(),
        # because Burp immediately and synchronously calls getUiComponent(),
        # which returns self._main_panel. If _main_panel doesn't exist yet,
        # you get: AttributeError: 'BurpExtender' object has no attribute '_main_panel'
        callbacks.addSuiteTab(self)

        # ---- INIT COMPLETE ----
        # This flag unblocks processHttpMessage. Set LAST, after every
        # attribute (including UI) has been initialized. Without this,
        # Burp can call processHttpMessage mid-init and crash with
        # AttributeError on _enabled_tool_flags / _stderr / _helpers.
        self._initialized = True

    # ===========================================================
    # ITab INTERFACE — Burp UI tab
    # ===========================================================

    def getTabCaption(self):
        return "SSO + License"

    def getUiComponent(self):
        # Defensive: if Burp calls this before _build_ui has run,
        # return an empty panel instead of crashing with AttributeError.
        if not hasattr(self, '_main_panel') or self._main_panel is None:
            return JPanel()
        return self._main_panel

    # ===========================================================
    # UI CONSTRUCTION
    # ===========================================================

    def _build_ui(self):
        """Build the configuration + status + log panel shown in Burp's
        'SSO + License' tab. All config fields are pre-filled with the
        current self.* values so the UI is the single source of truth
        after you click 'Save Configuration'."""
        self._main_panel = JPanel()
        self._main_panel.setLayout(BoxLayout(self._main_panel, BoxLayout.Y_AXIS))

        # ---------- CONFIG PANEL ----------
        config_panel = JPanel()
        config_panel.setLayout(BoxLayout(config_panel, BoxLayout.Y_AXIS))
        config_panel.setBorder(BorderFactory.createTitledBorder(
            "Configuration (edit, then click Save Configuration)"))

        def add_field_row(label_text, default_value, cols=50):
            row = JPanel(FlowLayout(FlowLayout.LEFT))
            lbl = JLabel(label_text)
            lbl.setPreferredSize(Dimension(160, 24))
            field = JTextField(str(default_value), cols)
            row.add(lbl)
            row.add(field)
            config_panel.add(row)
            return field

        self._ui_sso_url            = add_field_row("SSO URL:", self.sso_url)
        self._ui_sso_cookies        = add_field_row("SSO Cookies:", self.sso_cookies)
        self._ui_token_url          = add_field_row("Token URL:", self.token_url)
        self._ui_logout_url         = add_field_row("Logout URL:", self.logout_url)
        self._ui_current_scan_user  = add_field_row("Current Scan User:", self.current_scan_user)
        self._ui_logout_targets     = add_field_row("Logout Targets (comma-sep):", ", ".join(self.logout_target_userids))

        # Tool checkboxes
        tools_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        tools_panel.add(JLabel("Enabled Tools:"))
        self._ui_tool_checks = {}
        for name in ["Proxy", "Repeater", "Intruder", "Scanner",
                     "Sequencer", "Decoder", "Comparer", "Extender",
                     "Target", "Spider", "Suite"]:
            cb = JCheckBox(name)
            cb.setSelected(name in self.enabled_tools)
            tools_panel.add(cb)
            self._ui_tool_checks[name] = cb
        config_panel.add(tools_panel)

        # Logout headers
        self._ui_company     = add_field_row("Defaultcompany:", self.logout_default_company, 30)
        self._ui_username    = add_field_row("Defaultusername:", self.logout_default_username, 30)
        self._ui_noos_1      = add_field_row("Noos 1:", self.logout_noos_1, 30)
        self._ui_noos_2      = add_field_row("Noos 2:", self.logout_noos_2, 30)
        self._ui_referer     = add_field_row("Referer:", self.logout_referer, 30)
        self._ui_origin      = add_field_row("Origin:", self.logout_origin, 30)
        self._ui_cooldown    = add_field_row("Cooldown (sec):", str(self.logout_cooldown_seconds), 10)
        self._ui_jsessionid_ttl = add_field_row("JSESSIONID TTL (sec):", str(self.JSESSIONID_TTL_SECONDS), 10)

        # License markers — multi-line text area (one per line)
        markers_row = JPanel(FlowLayout(FlowLayout.LEFT))
        markers_row.add(JLabel("License Exhaustion Markers (one per line):"))
        markers_area = JTextArea(6, 50)
        markers_area.setText("\n".join(self.license_exhausted_markers))
        markers_row.add(JScrollPane(markers_area))
        config_panel.add(markers_row)
        self._ui_markers = markers_area

        # Save button
        save_btn = JButton("Save Configuration", actionPerformed=self._save_config)
        config_panel.add(save_btn)

        self._main_panel.add(config_panel)

        # ---------- STATUS PANEL ----------
        status_panel = JPanel()
        status_panel.setLayout(BoxLayout(status_panel, BoxLayout.Y_AXIS))
        status_panel.setBorder(BorderFactory.createTitledBorder("Session Status (live — updates every 2s)"))

        self._ui_jwt_status         = JLabel("JWT: not loaded")
        self._ui_jsessionid_status  = JLabel("JSESSIONID: not loaded")
        self._ui_last_refresh_label = JLabel("Last JWT refresh: never")
        self._ui_last_logout_label  = JLabel("Last logout: never")

        for lbl in [self._ui_jwt_status, self._ui_jsessionid_status,
                    self._ui_last_refresh_label, self._ui_last_logout_label]:
            status_panel.add(lbl)

        btn_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        btn_panel.add(JButton("Refresh JWT Now", actionPerformed=self._manual_refresh_jwt))
        btn_panel.add(JButton("Free One License Now", actionPerformed=self._manual_free_license))
        btn_panel.add(JButton("Clear Log", actionPerformed=self._clear_log))
        status_panel.add(btn_panel)

        self._main_panel.add(status_panel)

        # ---------- ACTIVITY LOG ----------
        log_panel = JPanel(BorderLayout())
        log_panel.setBorder(BorderFactory.createTitledBorder("Activity Log (newest at bottom)"))
        log_panel.setPreferredSize(Dimension(900, 180))
        self._ui_log = JTextArea()
        self._ui_log.setEditable(False)
        # getFont() may return None on a freshly-constructed JTextArea in
        # some Jython/Swing combos — guard against that.
        try:
            current_font = self._ui_log.getFont()
            if current_font is not None and hasattr(current_font, 'deriveFont'):
                self._ui_log.setFont(current_font.deriveFont(11.0))
        except Exception:
            pass  # leave the default font
        log_panel.add(JScrollPane(self._ui_log), BorderLayout.CENTER)
        self._main_panel.add(log_panel)

    # ===========================================================
    # UI ACTIONS (run on EDT via Swing button dispatch)
    # ===========================================================

    def _save_config(self, event):
        """Read every field from the UI and write it back to self.*.
        This is what makes the UI the single source of truth."""
        try:
            self.sso_url              = self._ui_sso_url.getText().strip()
            self.sso_cookies          = self._ui_sso_cookies.getText().strip()
            self.token_url            = self._ui_token_url.getText().strip()
            self.logout_url           = self._ui_logout_url.getText().strip()
            self.current_scan_user    = self._ui_current_scan_user.getText().strip()

            targets_text = self._ui_logout_targets.getText().strip()
            self.logout_target_userids = [t.strip() for t in targets_text.split(",") if t.strip()]

            self.enabled_tools = set()
            for name, cb in self._ui_tool_checks.items():
                if cb.isSelected():
                    self.enabled_tools.add(name)

            # Rebuild the integer flag set
            name_to_flag = {
                "Proxy": TOOL_PROXY, "Repeater": TOOL_REPEATER, "Intruder": TOOL_INTRUDER,
                "Scanner": TOOL_SCANNER, "Sequencer": TOOL_SEQUENCER, "Decoder": TOOL_DECODER,
                "Comparer": TOOL_COMPARER, "Extender": TOOL_EXTENDER, "Target": TOOL_TARGET,
                "Spider": TOOL_SPIDER, "Suite": TOOL_SUIT,
            }
            self._enabled_tool_flags = set()
            for name in self.enabled_tools:
                flag = name_to_flag.get(name)
                if flag is not None:
                    self._enabled_tool_flags.add(flag)

            # Logout headers
            self.logout_default_company  = self._ui_company.getText().strip()
            self.logout_default_username = self._ui_username.getText().strip()
            self.logout_noos_1           = self._ui_noos_1.getText().strip()
            self.logout_noos_2           = self._ui_noos_2.getText().strip()
            self.logout_referer          = self._ui_referer.getText().strip()
            self.logout_origin           = self._ui_origin.getText().strip()
            self.logout_cooldown_seconds = int(self._ui_cooldown.getText().strip() or "15")
            self.JSESSIONID_TTL_SECONDS  = int(self._ui_jsessionid_ttl.getText().strip() or "900")

            # Markers — one per non-empty line
            markers_text = self._ui_markers.getText()
            self.license_exhausted_markers = [
                line.strip() for line in markers_text.split("\n") if line.strip()
            ]

            self._log_event("Configuration saved from UI")
            self._log_event("  - Logout targets: " + str(len(self.logout_target_userids)))
            self._log_event("  - Enabled tools: " + ", ".join(self.enabled_tools))
            self._log_event("  - License markers: " + str(len(self.license_exhausted_markers)))
        except Exception as e:
            self._log_event("ERROR saving config: " + str(e))
            self._stderr.println("_save_config error: " + str(e))

    def _manual_refresh_jwt(self, event):
        """Manual button — refresh JWT chain right now, off the EDT."""
        self._log_event("Manual JWT refresh triggered")
        Thread(ManualRefreshRunner(self)).start()

    def _manual_free_license(self, event):
        """Manual button — try to free one license right now, off the EDT."""
        self._log_event("Manual license-free triggered")
        Thread(ManualLogoutRunner(self)).start()

    def _clear_log(self, event):
        self._ui_log_buffer = []
        self._ui_log.setText("")

    # ===========================================================
    # LIVE STATUS UPDATER (Swing Timer, fires on EDT every 2s)
    # ===========================================================

    def _start_status_timer(self):
        """Start a 2-second Swing Timer that refreshes the status labels.
        Swing Timer fires on the EDT, so JLabel.setText is safe here."""
        self._status_timer = Timer(2000, StatusUpdateAction(self))
        self._status_timer.start()

    def _update_status_labels(self):
        """Called by the timer. Reads current state and updates labels.
        Runs on EDT, so direct JLabel.setText is OK."""
        try:
            # JWT status
            if not self._jwt_token:
                jwt_text = "JWT: not loaded"
            else:
                # Show first 20 chars + expiry
                prefix = self._jwt_token[:20] + "..."
                if self._is_jwt_expired(self._jwt_token):
                    jwt_text = "JWT: " + prefix + " (EXPIRED — will refresh on next request)"
                else:
                    # Decode exp for countdown
                    try:
                        parts = self._jwt_token.split(".")
                        payload = parts[1] + "=" * (4 - len(parts[1]) % 4)
                        data = json.loads(base64.urlsafe_b64decode(payload))
                        exp = data.get("exp", 0)
                        remaining = int(exp - time.time())
                        mins, secs = divmod(remaining, 60)
                        jwt_text = "JWT: " + prefix + " (expires in " + str(mins) + "m " + str(secs) + "s)"
                    except Exception:
                        jwt_text = "JWT: " + prefix + " (expiry unknown)"
            self._ui_jwt_status.setText(jwt_text)

            # JSESSIONID status
            if not self._jsessionid:
                self._ui_jsessionid_status.setText("JSESSIONID: not loaded")
            else:
                age = int(time.time() - self._jsessionid_fetched_at)
                remaining_ttl = self.JSESSIONID_TTL_SECONDS - age
                prefix = self._jsessionid[:16] + "..."
                if remaining_ttl > 0:
                    self._ui_jsessionid_status.setText(
                        "JSESSIONID: " + prefix + " (age " + str(age) + "s, TTL " + str(remaining_ttl) + "s left)")
                else:
                    self._ui_jsessionid_status.setText(
                        "JSESSIONID: " + prefix + " (age " + str(age) + "s, TTL EXCEEDED — will refresh on next use)")

            # Last refresh
            if self._last_refresh_time > 0:
                ago = int(time.time() - self._last_refresh_time)
                self._ui_last_refresh_label.setText("Last JWT refresh: " + str(ago) + "s ago")
            else:
                self._ui_last_refresh_label.setText("Last JWT refresh: never")

            # Last logout
            self._ui_last_logout_label.setText("Last logout: " + self._last_logout_time_str)
        except Exception as e:
            # Don't let status update crash the timer
            pass

    # ===========================================================
    # ACTIVITY LOG (thread-safe append via SwingUtilities)
    # ===========================================================

    def _log_event(self, msg):
        """Append a timestamped line to both the Burp Output tab and the
        UI activity log. Safe to call from any thread."""
        timestamp = time.strftime("%H:%M:%S")
        line = "[" + timestamp + "] " + msg
        self._stdout.println(msg)
        self._ui_log_buffer.append(line + "\n")
        # Trim to last N lines
        if len(self._ui_log_buffer) > self._ui_log_max:
            self._ui_log_buffer = self._ui_log_buffer[-self._ui_log_max:]
        # Update the text area on the EDT
        if hasattr(self, '_ui_log') and self._ui_log:
            SwingUtilities.invokeLater(LogAppender(self, "".join(self._ui_log_buffer[-50:])))

    # ----------------------------------------------------------
    # MAIN HTTP LISTENER ENTRY POINT
    # ----------------------------------------------------------
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # ---- INIT GUARD (race condition) ----
        # Burp may call processHttpMessage BEFORE registerExtenderCallbacks
        # has finished setting up self._enabled_tool_flags, self._stderr, etc.
        # If we don't guard, we crash with AttributeError on those attributes.
        # Silent return is correct here — there's nothing to inspect yet.
        if not getattr(self, '_initialized', False):
            return

        try:
            if messageIsRequest:
                return

            # ---- TOOL SCOPE FILTER ----
            # Only act on responses from tools we've explicitly enabled.
            # Without this, every Proxy browse / Spider crawl / Target
            # site-map request would trigger inspection and possibly
            # spurious refresh or logout attempts.
            if toolFlag not in self._enabled_tool_flags:
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
                tool_name = TOOL_NAMES.get(toolFlag, "Unknown")
                self._log_event("JWT expired detected in " + tool_name + " response — starting refresh flow")

                if not self._refresh_full_jwt_chain():
                    self._log_event("FAILED — could not refresh JWT chain")
                    return
                self._last_refresh_time = time.time()

                self._log_event("JWT refresh complete — retrying original request")
                self._retry_with_new_jwt(messageInfo)
                return

            # ---------------------------------------------------
            # PATH B: License exhausted -> logout a stale user, then retry
            # ---------------------------------------------------
            if self._is_license_exhausted(resp_body, resp_info.getStatusCode()):
                tool_name = TOOL_NAMES.get(toolFlag, "Unknown")
                self._log_event("License exhaustion detected in " + tool_name + " response — attempting logout")
                freed = self._free_one_license()
                if freed:
                    self._log_event("License freed — retrying original request")
                    # JWT should still be valid here (it was valid enough to
                    # reach the app and get a "license full" response).
                    # If it has also expired, the retry will trigger Path A.
                    self._retry_original(messageInfo)
                else:
                    self._log_event("Could not free a license — manual intervention required")
                return

        except Exception as e:
            # Defensive: _stderr may not exist if we crashed mid-init
            if hasattr(self, '_stderr') and self._stderr is not None:
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
                    self._last_logout_user = uid
                    self._last_logout_time_str = time.strftime("%H:%M:%S") + " (user: " + uid + ")"
                    self._log_event("License freed by logging out user: " + uid)
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


# ===========================================================
# HELPER RUNNABLES (module-level, used by the UI buttons and
# status timer — must be outside the class body so Jython can
# reference them at class-definition time)
# ===========================================================

class StatusUpdateAction(ActionListener):
    """Fires every 2s on the EDT — calls the extension's label updater."""
    def __init__(self, ext):
        self.ext = ext
    def actionPerformed(self, event):
        self.ext._update_status_labels()


class LogAppender(Runnable):
    """Updates the UI log text area on the EDT (safe)."""
    def __init__(self, ext, text):
        self.ext = ext
        self.text = text
    def run(self):
        try:
            self.ext._ui_log.setText(self.text)
            self.ext._ui_log.setCaretPosition(self.ext._ui_log.getDocument().getLength())
        except Exception:
            pass


class ManualRefreshRunner(Runnable):
    """Runs the full JWT refresh chain on a background thread so the
    EDT is not blocked when you click 'Refresh JWT Now'."""
    def __init__(self, ext):
        self.ext = ext
    def run(self):
        try:
            ok = self.ext._refresh_full_jwt_chain()
            if ok:
                self.ext._last_refresh_time = time.time()
                self.ext._log_event("Manual JWT refresh: SUCCESS")
            else:
                self.ext._log_event("Manual JWT refresh: FAILED (see Burp Errors tab)")
        except Exception as e:
            self.ext._log_event("Manual JWT refresh error: " + str(e))


class ManualLogoutRunner(Runnable):
    """Runs the license-free flow on a background thread."""
    def __init__(self, ext):
        self.ext = ext
    def run(self):
        try:
            ok = self.ext._free_one_license()
            if ok:
                self.ext._log_event("Manual license-free: SUCCESS")
            else:
                self.ext._log_event("Manual license-free: FAILED (see Burp Errors tab)")
        except Exception as e:
            self.ext._log_event("Manual license-free error: " + str(e))
