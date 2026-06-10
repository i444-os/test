# ================================================================
# Burp Suite Header & Parameter Stripper Extension
# Compatible with Jython 2.7.4
# Version: 2.0.0
# ================================================================
#
# CHANGELOG v2.0.0:
#   CRITICAL FIXES:
#   - FIX: Java byte[] slicing replaced with ArrayList-based body
#     extraction. In Jython, slicing a Java byte[] can return
#     PyArray instead of byte[], causing buildHttpMessage to
#     fail silently.
#   - FIX: Python lists replaced with java.util.ArrayList when
#     passing to Java methods. Some Burp versions are strict
#     about List<String> vs PyList type matching.
#   - FIX: toolFlag comparison now uses explicit int() cast to
#     avoid Java Integer vs Python int mismatch in set lookups.
#   - FIX: Exception handling now includes traceback info.
#   IMPROVEMENTS:
#   - ADDED: Debug mode checkbox for verbose logging.
#   - ADDED: Comprehensive debug logging in processHttpMessage
#     so every step of the flow is traceable.
#   - ADDED: Debug logging in _strip_headers for header-level
#     match/no-match tracing.
#   - ADDED: "Test Match" button to verify pattern matching
#     without needing to send actual requests.
#   - ADDED: Body extraction uses safe fallback: tries byte
#     slicing first, falls back to string-based extraction.
#
# Features:
#   - Remove specified headers from HTTP requests
#   - Remove specified parameters from HTTP requests (future-ready)
#   - Select which Burp tools to apply stripping to
#   - Start/Stop extension at any time
#   - Case-sensitive / Case-insensitive matching
#   - Regex pattern matching mode
#   - Partial (substring) matching mode
#   - Activity log with auto-scroll
#   - Live statistics counter
#   - Import/Export configuration files
#   - Select All / Deselect All tool checkboxes
#   - Debug mode for troubleshooting
#   - Test Match button for pattern verification
#   - Thread-safe operation with proper Swing EDT handling
#
# Usage:
#   1. Load in Burp Suite: Extender -> Extensions -> Add -> Python
#   2. Select this file as the extension
#   3. Configure headers/parameters to strip in the "H&P Stripper" tab
#   4. Select which Burp tools should have stripping applied
#   5. Click "Start" to begin processing
#   6. Enable "Debug" checkbox if you need to trace issues
#
# Jython 2.7.4 Compatibility Notes:
#   - No f-strings (Python 3.6+)
#   - No super() without arguments in old-style classes
#   - Java List slicing requires conversion to Python list first
#   - Use .append() not .add() for Python lists
#   - Use ArrayList.add() not .append() for Java lists
#   - Swing UI updates must run on EDT via SwingUtilities.invokeLater
#   - threading.Lock supports context manager (with statement)
#   - re module is available and works identically to CPython 2.7
#   - Java byte[] slicing may return PyArray, NOT byte[]
#   - Python list is NOT always accepted as Java List<String>
# ================================================================

from burp import IBurpExtender, ITab, IHttpListener, IExtensionStateListener
from java.awt import (Dimension, Font, Color, FlowLayout, BorderLayout,
                       GridBagLayout, GridBagConstraints, Insets)
from javax.swing import (JPanel, JLabel, JCheckBox, JButton, JTextArea,
                          JScrollPane, JTabbedPane, SwingUtilities,
                          JTextField, JComboBox, Box)
from javax.swing.border import EmptyBorder, TitledBorder, EtchedBorder, CompoundBorder
from javax.swing.filechooser import FileNameExtensionFilter
from java.awt.event import ActionListener
from java.lang import Runnable
from java.util import ArrayList
import re
import threading
import time
import traceback

# ============================================================
# Burp Suite Tool Flag Constants
# ============================================================
TOOL_PROXY = 2
TOOL_SPIDER = 3
TOOL_SCANNER = 4
TOOL_INTRUDER = 5
TOOL_REPEATER = 6
TOOL_SEQUENCER = 7
TOOL_DECODER = 8
TOOL_COMPARER = 9
TOOL_EXTENDER = 10
TOOL_TARGET = 1

# Ordered tool mapping for UI display (matches user's requested order)
TOOL_MAP_ORDERED = [
    (TOOL_TARGET,    "Target"),
    (TOOL_INTRUDER,  "Intruder"),
    (TOOL_EXTENDER,  "Extensions"),
    (TOOL_SCANNER,   "Scanner"),
    (TOOL_SEQUENCER, "Sequencer"),
    (TOOL_PROXY,     "Proxy (use with caution)"),
    (TOOL_REPEATER,  "Repeater"),
]

# Parameter type constants (Burp API IParameter)
PARAM_URL = 0
PARAM_BODY = 1
PARAM_COOKIE = 2
PARAM_XML = 3
PARAM_XML_ATTR = 4
PARAM_MULTIPART_ATTR = 5
PARAM_JSON = 6

PARAM_TYPE_NAMES = {
    PARAM_URL: "URL",
    PARAM_BODY: "Body",
    PARAM_COOKIE: "Cookie",
    PARAM_XML: "XML",
    PARAM_XML_ATTR: "XMLAttr",
    PARAM_MULTIPART_ATTR: "Multipart",
    PARAM_JSON: "JSON",
}


# ============================================================
# Core Matching Logic (extracted for testability)
# ============================================================

def should_match(name, patterns, case_sensitive, regex_mode, partial_match):
    """
    Check if a name matches any of the given patterns.

    This is the core matching engine. It supports three modes:
      - Exact match (default): name must equal pattern (case-insensitive by default)
      - Partial match: pattern must be a substring of name
      - Regex match: pattern is treated as a regular expression

    Args:
        name: The header name or parameter name to check (string)
        patterns: List of pattern strings to match against
        case_sensitive: If True, match is case-sensitive
        regex_mode: If True, patterns are treated as regex
        partial_match: If True, patterns match as substrings

    Returns:
        True if name matches any pattern, False otherwise
    """
    if not patterns:
        return False

    for pattern in patterns:
        if not pattern:
            continue

        if regex_mode:
            try:
                flags = 0 if case_sensitive else re.IGNORECASE
                if re.search(pattern, name, flags):
                    return True
            except re.error:
                continue
        elif partial_match:
            if case_sensitive:
                if pattern in name:
                    return True
            else:
                if pattern.lower() in name.lower():
                    return True
        else:
            # Exact match mode
            if case_sensitive:
                if name == pattern:
                    return True
            else:
                if name.lower() == pattern.lower():
                    return True

    return False


def parse_text_entries(text, is_header=False):
    """
    Parse text area content into a list of cleaned entries.

    Rules:
      - Blank lines are ignored
      - Lines starting with # are comments (ignored)
      - For headers: trailing colons are stripped, "Name: Value" entries
        are cleaned to just "Name"
      - Whitespace is trimmed
      - \r characters are stripped (Windows line endings)

    Args:
        text: Raw text from the text area
        is_header: If True, apply header-specific cleaning (strip colons/values)

    Returns:
        List of cleaned entry strings
    """
    if not text or not text.strip():
        return []

    entries = []
    for line in text.split("\n"):
        # Strip \r from Windows line endings AND surrounding whitespace
        line = line.strip().rstrip("\r")
        if not line or line.startswith("#"):
            continue

        if is_header:
            # Strip trailing colon (e.g., "Authorization:" -> "Authorization")
            if line.endswith(":"):
                line = line[:-1].strip()
            # Handle "Name: Value" pattern (e.g., "Authorization: Bearer xxx")
            # Only strip if there's a space after the colon, indicating a value
            if ": " in line:
                line = line.split(": ", 1)[0].strip()

        if line:
            entries.append(line)

    return entries


# ============================================================
# Main Extension Class
# ============================================================

class BurpExtender(IBurpExtender, ITab, IHttpListener, IExtensionStateListener):
    """
    Burp Suite extension for stripping headers and parameters from HTTP requests.

    Implements:
      - IBurpExtender: Required entry point for all Burp extensions
      - ITab: Provides a custom UI tab in Burp's main window
      - IHttpListener: Intercepts HTTP messages passing through Burp
      - IExtensionStateListener: Handles extension unload events
    """

    def registerExtenderCallbacks(self, callbacks):
        """
        Entry point called by Burp Suite when the extension is loaded.
        Initializes all state, builds UI, and registers listeners.
        """
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._is_running = False
        self._lock = threading.Lock()

        # Debug mode flag
        self._debug = False

        # Statistics counters (thread-safe via _stats_lock)
        self._stats_headers_removed = 0
        self._stats_params_removed = 0
        self._stats_requests_processed = 0
        self._stats_lock = threading.Lock()

        # Activity log (thread-safe via _log_lock)
        self._log_entries = []
        self._log_lock = threading.Lock()

        # Set extension name
        callbacks.setExtensionName("H&P Stripper")

        # Build the UI
        self._build_ui()

        # Register listeners
        callbacks.registerHttpListener(self)
        callbacks.registerExtensionStateListener(self)

        # Add our custom tab to Burp's UI
        callbacks.addSuiteTab(self)

        # Auto-start the extension
        self._start_extension()

        self._add_log("INFO", "Extension loaded successfully. Version 2.0.0")
        self._add_log("INFO", "Configure headers/parameters to strip, select tools, then click Start.")
        self._add_log("INFO", "Enable 'Debug' checkbox for verbose logging if headers are not being removed.")

    # ============================================================
    # UI Construction
    # ============================================================

    def _build_ui(self):
        """Build the complete extension UI panel."""
        self._panel = JPanel(BorderLayout(5, 5))
        self._panel.setBorder(EmptyBorder(8, 8, 8, 8))

        # NORTH: Control panel (tool checkboxes + start/stop)
        self._panel.add(self._build_control_panel(), BorderLayout.NORTH)

        # CENTER: Tabbed pane for Header and Parameter configuration
        self._tabbed_pane = JTabbedPane()
        self._tabbed_pane.addTab("Header Stripper", self._build_header_panel())
        self._tabbed_pane.addTab("Parameter Stripper", self._build_parameter_panel())
        self._panel.add(self._tabbed_pane, BorderLayout.CENTER)

        # SOUTH: Statistics + Activity log
        south_panel = JPanel(BorderLayout(5, 5))
        south_panel.add(self._build_stats_panel(), BorderLayout.NORTH)
        south_panel.add(self._build_log_panel(), BorderLayout.CENTER)
        self._panel.add(south_panel, BorderLayout.SOUTH)

    def _build_header_panel(self):
        """Build the header stripping configuration panel."""
        panel = JPanel(BorderLayout(5, 5))
        panel.setBorder(EmptyBorder(8, 8, 8, 8))

        # Info label
        info = JLabel(
            "<html><b>Enter header names to remove</b> (one per line, "
            "case-insensitive by default)<br/>"
            "Lines starting with # are comments. "
            "Examples: X-Forwarded-For, Authorization, Cookie, Accept-Encoding</html>"
        )
        panel.add(info, BorderLayout.NORTH)

        # Text area for header names
        self._header_text = JTextArea(12, 40)
        self._header_text.setFont(Font("Monospaced", Font.PLAIN, 13))
        self._header_text.setToolTipText(
            "Enter one header name per line to remove from requests. "
            "Use # for comments."
        )
        scroll = JScrollPane(self._header_text)
        scroll.setBorder(CompoundBorder(
            TitledBorder(EtchedBorder(), "Headers to Remove"),
            EmptyBorder(5, 5, 5, 5)
        ))
        panel.add(scroll, BorderLayout.CENTER)

        # Options row
        opts = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))

        self._header_case_sensitive = JCheckBox("Case-sensitive", False)
        self._header_regex_mode = JCheckBox("Regex mode", False)
        self._header_partial_match = JCheckBox("Partial match", False)

        self._header_case_sensitive.setToolTipText(
            "Match header names exactly (case-sensitive)"
        )
        self._header_regex_mode.setToolTipText(
            "Treat each entry as a regular expression pattern"
        )
        self._header_partial_match.setToolTipText(
            "Match if the header name contains the pattern as a substring"
        )

        opts.add(JLabel("Matching:"))
        opts.add(self._header_case_sensitive)
        opts.add(self._header_regex_mode)
        opts.add(self._header_partial_match)

        # Separator
        opts.add(JLabel("   "))

        # Import/Export buttons
        import_btn = JButton("Import")
        export_btn = JButton("Export")
        test_btn = JButton("Test Match")
        import_btn.setToolTipText("Import header list from a text file")
        export_btn.setToolTipText("Export header list to a text file")
        test_btn.setToolTipText(
            "Test if your patterns match sample header names. "
            "Results appear in the Activity Log."
        )
        import_btn.addActionListener(ImportListener(self, "header"))
        export_btn.addActionListener(ExportListener(self, "header"))
        test_btn.addActionListener(TestMatchListener(self, "header"))
        opts.add(import_btn)
        opts.add(export_btn)
        opts.add(test_btn)

        panel.add(opts, BorderLayout.SOUTH)
        return panel

    def _build_parameter_panel(self):
        """Build the parameter stripping configuration panel."""
        panel = JPanel(BorderLayout(5, 5))
        panel.setBorder(EmptyBorder(8, 8, 8, 8))

        # Info label
        info = JLabel(
            "<html><b>Enter parameter names to remove</b> (one per line, "
            "case-insensitive by default)<br/>"
            "Lines starting with # are comments. "
            "Examples: tracking_id, session, debug, utm_source</html>"
        )
        panel.add(info, BorderLayout.NORTH)

        # Text area for parameter names
        self._param_text = JTextArea(12, 40)
        self._param_text.setFont(Font("Monospaced", Font.PLAIN, 13))
        self._param_text.setToolTipText(
            "Enter one parameter name per line to remove from requests. "
            "Use # for comments."
        )
        scroll = JScrollPane(self._param_text)
        scroll.setBorder(CompoundBorder(
            TitledBorder(EtchedBorder(), "Parameters to Remove"),
            EmptyBorder(5, 5, 5, 5)
        ))
        panel.add(scroll, BorderLayout.CENTER)

        # Options row - parameter types + matching options
        opts = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))

        # Parameter type checkboxes
        self._param_url = JCheckBox("URL", True)
        self._param_body = JCheckBox("Body", True)
        self._param_cookie = JCheckBox("Cookie", True)
        self._param_json = JCheckBox("JSON", True)
        self._param_xml = JCheckBox("XML", True)
        self._param_multipart = JCheckBox("Multipart", True)

        self._param_url.setToolTipText("Strip URL query parameters")
        self._param_body.setToolTipText("Strip body/form parameters")
        self._param_cookie.setToolTipText("Strip cookie parameters")
        self._param_json.setToolTipText("Strip JSON body parameters")
        self._param_xml.setToolTipText("Strip XML and XML attribute parameters")
        self._param_multipart.setToolTipText("Strip multipart attribute parameters")

        opts.add(JLabel("Param Types:"))
        opts.add(self._param_url)
        opts.add(self._param_body)
        opts.add(self._param_cookie)
        opts.add(self._param_json)
        opts.add(self._param_xml)
        opts.add(self._param_multipart)

        # Separator
        opts.add(JLabel("   "))

        # Matching options
        self._param_case_sensitive = JCheckBox("Case-sensitive", False)
        self._param_regex_mode = JCheckBox("Regex mode", False)
        self._param_partial_match = JCheckBox("Partial match", False)

        self._param_case_sensitive.setToolTipText(
            "Match parameter names exactly (case-sensitive)"
        )
        self._param_regex_mode.setToolTipText(
            "Treat each entry as a regular expression pattern"
        )
        self._param_partial_match.setToolTipText(
            "Match if the parameter name contains the pattern as a substring"
        )

        opts.add(JLabel("Matching:"))
        opts.add(self._param_case_sensitive)
        opts.add(self._param_regex_mode)
        opts.add(self._param_partial_match)

        # Separator
        opts.add(JLabel("   "))

        # Import/Export/Test buttons
        import_btn = JButton("Import")
        export_btn = JButton("Export")
        test_btn = JButton("Test Match")
        import_btn.setToolTipText("Import parameter list from a text file")
        export_btn.setToolTipText("Export parameter list to a text file")
        test_btn.setToolTipText(
            "Test if your patterns match sample parameter names. "
            "Results appear in the Activity Log."
        )
        import_btn.addActionListener(ImportListener(self, "param"))
        export_btn.addActionListener(ExportListener(self, "param"))
        test_btn.addActionListener(TestMatchListener(self, "param"))
        opts.add(import_btn)
        opts.add(export_btn)
        opts.add(test_btn)

        panel.add(opts, BorderLayout.SOUTH)
        return panel

    def _build_control_panel(self):
        """Build the control panel with tool checkboxes and start/stop buttons."""
        panel = JPanel(BorderLayout(5, 5))

        # Tool checkboxes panel
        tool_panel = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        tool_panel.setBorder(CompoundBorder(
            TitledBorder(EtchedBorder(),
                         "Active Tools (select which Burp tools to apply stripping to)"),
            EmptyBorder(5, 5, 5, 5)
        ))

        self._tool_checkboxes = {}
        for tool_flag, tool_name in TOOL_MAP_ORDERED:
            if "Proxy" in tool_name:
                cb = JCheckBox(tool_name, False)
                cb.setToolTipText(
                    "CAUTION: Modifying proxy traffic may break normal browsing. "
                    "Enable only when you understand the implications."
                )
            else:
                cb = JCheckBox(tool_name, True)
                cb.setToolTipText(
                    "Apply stripping to %s requests" % tool_name
                )
            self._tool_checkboxes[tool_flag] = cb
            tool_panel.add(cb)

        # Select All / Deselect All buttons
        select_all_btn = JButton("Select All")
        deselect_all_btn = JButton("Deselect All")
        select_all_btn.setToolTipText("Check all tool checkboxes")
        deselect_all_btn.setToolTipText("Uncheck all tool checkboxes")
        select_all_btn.addActionListener(SelectAllToolsListener(self, True))
        deselect_all_btn.addActionListener(SelectAllToolsListener(self, False))
        tool_panel.add(select_all_btn)
        tool_panel.add(deselect_all_btn)

        panel.add(tool_panel, BorderLayout.CENTER)

        # Start/Stop + Status + Debug panel
        button_panel = JPanel(FlowLayout(FlowLayout.RIGHT, 6, 2))
        button_panel.setBorder(EmptyBorder(5, 5, 5, 5))

        self._start_btn = JButton("Start")
        self._stop_btn = JButton("Stop")
        self._stop_btn.setEnabled(False)
        self._clear_log_btn = JButton("Clear Log")
        self._debug_cb = JCheckBox("Debug", False)

        self._start_btn.setToolTipText("Start request modification")
        self._stop_btn.setToolTipText("Stop request modification")
        self._clear_log_btn.setToolTipText("Clear the activity log")
        self._debug_cb.setToolTipText(
            "Enable verbose debug logging to trace request processing. "
            "Check this if headers are not being removed as expected."
        )

        self._status_label = JLabel("STOPPED")
        self._status_label.setFont(Font("SansSerif", Font.BOLD, 13))
        self._status_label.setForeground(Color(204, 0, 0))  # Dark red

        self._start_btn.addActionListener(StartListener(self))
        self._stop_btn.addActionListener(StopListener(self))
        self._clear_log_btn.addActionListener(ClearLogListener(self))
        self._debug_cb.addActionListener(DebugToggleListener(self))

        button_panel.add(self._debug_cb)
        button_panel.add(self._clear_log_btn)
        button_panel.add(self._start_btn)
        button_panel.add(self._stop_btn)
        button_panel.add(JLabel("  Status: "))
        button_panel.add(self._status_label)

        panel.add(button_panel, BorderLayout.EAST)
        return panel

    def _build_stats_panel(self):
        """Build the statistics display panel."""
        panel = JPanel(FlowLayout(FlowLayout.LEFT, 15, 2))
        panel.setBorder(CompoundBorder(
            TitledBorder(EtchedBorder(), "Statistics"),
            EmptyBorder(3, 5, 3, 5)
        ))

        self._stats_label = JLabel(
            "Headers removed: 0 | Parameters removed: 0 | Requests processed: 0"
        )
        self._stats_label.setFont(Font("SansSerif", Font.PLAIN, 12))
        panel.add(self._stats_label)

        reset_stats_btn = JButton("Reset Stats")
        reset_stats_btn.setToolTipText("Reset all statistics counters to zero")
        reset_stats_btn.addActionListener(ResetStatsListener(self))
        panel.add(reset_stats_btn)

        return panel

    def _build_log_panel(self):
        """Build the activity log panel."""
        panel = JPanel(BorderLayout(5, 5))
        panel.setPreferredSize(Dimension(800, 140))
        panel.setBorder(CompoundBorder(
            TitledBorder(EtchedBorder(), "Activity Log"),
            EmptyBorder(5, 5, 5, 5)
        ))

        self._log_text = JTextArea(5, 30)
        self._log_text.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._log_text.setEditable(False)
        scroll = JScrollPane(self._log_text)
        panel.add(scroll, BorderLayout.CENTER)

        return panel

    # ============================================================
    # Extension Start / Stop
    # ============================================================

    def _start_extension(self):
        """Start the extension - begin processing requests."""
        with self._lock:
            self._is_running = True
        SwingUtilities.invokeLater(SetStatusRunnable(self, True))

    def _stop_extension(self):
        """Stop the extension - stop processing requests."""
        with self._lock:
            self._is_running = False
        SwingUtilities.invokeLater(SetStatusRunnable(self, False))

    def _is_running_safe(self):
        """Thread-safe check if the extension is currently running."""
        with self._lock:
            return self._is_running

    def _get_active_tools(self):
        """Get the set of currently active tool flags from checkboxes."""
        active = set()
        for tool_flag, cb in self._tool_checkboxes.items():
            if cb.isSelected():
                active.add(int(tool_flag))
        return active

    # ============================================================
    # IHttpListener Implementation
    # ============================================================

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """
        Called by Burp for each HTTP message passing through any tool.

        Only processes requests (not responses), only when extension is running,
        and only for tools whose checkboxes are checked.
        """
        # Only process requests, not responses
        if not messageIsRequest:
            return

        # Force Python int from Java int for reliable set comparison
        tool_flag = int(toolFlag)

        # Check if extension is running
        if not self._is_running_safe():
            return

        # Check if this tool is in the active set
        active_tools = self._get_active_tools()
        if tool_flag not in active_tools:
            if self._debug:
                self._add_log("DEBUG", "Skipping tool=%d (not in active set %s)" % (tool_flag, str(active_tools)))
            return

        # Get the request bytes
        request = messageInfo.getRequest()
        if request is None:
            if self._debug:
                self._add_log("DEBUG", "Request is None, skipping")
            return

        try:
            modified = False
            modified_request = request

            # ---- Strip Headers ----
            header_patterns = self._get_header_patterns()
            if self._debug:
                self._add_log("DEBUG", "[%s] Header patterns: %s" % (self._get_tool_name(tool_flag), str(header_patterns)))

            if header_patterns:
                modified_request, removed_headers = self._strip_headers(
                    modified_request, header_patterns
                )
                if removed_headers:
                    modified = True
                    with self._stats_lock:
                        self._stats_headers_removed += len(removed_headers)
                    tool_name = self._get_tool_name(tool_flag)
                    for h in removed_headers:
                        self._add_log("HEADER", "[%s] Removed: %s" % (tool_name, h))
                elif self._debug:
                    self._add_log("DEBUG", "[%s] No headers matched for removal" % self._get_tool_name(tool_flag))
            else:
                if self._debug:
                    self._add_log("DEBUG", "[%s] No header patterns configured" % self._get_tool_name(tool_flag))

            # ---- Strip Parameters ----
            param_patterns = self._get_param_patterns()
            if param_patterns:
                modified_request, removed_params = self._strip_parameters(
                    modified_request, param_patterns
                )
                if removed_params:
                    modified = True
                    with self._stats_lock:
                        self._stats_params_removed += len(removed_params)
                    tool_name = self._get_tool_name(tool_flag)
                    for p in removed_params:
                        self._add_log("PARAM", "[%s] Removed: %s" % (tool_name, p))

            # Update the request if any modifications were made
            if modified:
                messageInfo.setRequest(modified_request)
                with self._stats_lock:
                    self._stats_requests_processed += 1
                SwingUtilities.invokeLater(UpdateStatsRunnable(self))
                if self._debug:
                    self._add_log("DEBUG", "[%s] Request modified successfully" % self._get_tool_name(tool_flag))

        except Exception as e:
            tb = traceback.format_exc()
            self._add_log("ERROR", "processHttpMessage: %s | Traceback: %s" % (str(e), tb))

    # ============================================================
    # Header Stripping Logic
    # ============================================================

    def _get_header_patterns(self):
        """Parse the header text area and return list of header patterns."""
        return parse_text_entries(self._header_text.getText(), is_header=True)

    def _get_param_patterns(self):
        """Parse the parameter text area and return list of parameter patterns."""
        return parse_text_entries(self._param_text.getText(), is_header=False)

    def _strip_headers(self, request, header_patterns):
        """
        Remove matching headers from an HTTP request.

        Uses java.util.ArrayList for header lists passed to Burp API methods,
        and safe body extraction to avoid Jython byte[] slicing issues.

        Args:
            request: The raw request bytes (Java byte[])
            header_patterns: List of header name patterns to match

        Returns:
            Tuple of (modified_request_bytes, list_of_removed_header_strings)
            If no headers were removed, returns (original_request, [])
        """
        try:
            request_info = self._helpers.analyzeRequest(request)

            # CRITICAL FIX: Convert Java List to Python list for safe indexing/slicing
            # Java Lists in Jython do NOT support Python-style slicing ([1:])
            original_headers = [h for h in request_info.getHeaders()]

            body_offset = request_info.getBodyOffset()

            if len(original_headers) == 0:
                return request, []

            # Read matching options from UI
            case_sensitive = self._header_case_sensitive.isSelected()
            regex_mode = self._header_regex_mode.isSelected()
            partial_match = self._header_partial_match.isSelected()

            # First header line is always the request line
            # (e.g., "GET /path HTTP/1.1") - must NEVER be removed
            request_line = original_headers[0]

            # CRITICAL FIX: Use java.util.ArrayList instead of Python list
            # Burp's buildHttpMessage expects java.util.List<String>,
            # and some Burp versions reject Python lists (PyList).
            new_headers = ArrayList()
            new_headers.add(request_line)

            removed = []

            if self._debug:
                self._add_log("DEBUG", "Analyzing %d headers for removal" % (len(original_headers) - 1))

            for header in original_headers[1:]:
                colon_idx = header.find(":")
                if colon_idx == -1:
                    # Malformed header without colon - keep as-is for safety
                    new_headers.add(header)
                    if self._debug:
                        self._add_log("DEBUG", "Kept malformed header (no colon): %s" % header)
                    continue

                header_name = header[:colon_idx].strip()

                if should_match(header_name, header_patterns,
                                case_sensitive, regex_mode, partial_match):
                    removed.append(header)
                    if self._debug:
                        self._add_log("DEBUG", "MATCHED header '%s' -> removing" % header_name)
                else:
                    new_headers.add(header)
                    if self._debug:
                        self._add_log("DEBUG", "No match for header '%s' -> keeping" % header_name)

            if removed:
                # CRITICAL FIX: Safe body extraction
                # In Jython, slicing a Java byte[] may return PyArray instead of byte[],
                # which causes buildHttpMessage to fail silently.
                # We use a try/except with fallback to string-based extraction.
                body = self._safe_extract_body(request, body_offset)

                if body is not None:
                    modified_request = self._helpers.buildHttpMessage(new_headers, body)
                    if self._debug:
                        self._add_log("DEBUG", "buildHttpMessage succeeded, new request created")
                    return modified_request, removed
                else:
                    self._add_log("ERROR", "Failed to extract body from request")
                    return request, []
            else:
                return request, []

        except Exception as e:
            tb = traceback.format_exc()
            self._add_log("ERROR", "_strip_headers: %s | Traceback: %s" % (str(e), tb))
            return request, []

    def _safe_extract_body(self, request, body_offset):
        """
        Safely extract the body bytes from a request.

        Method 1: Direct byte array slicing (works in most Jython versions)
        Method 2: String-based extraction using bytesToString/stringToBytes
        Method 3: Manual byte copy

        Returns:
            byte[] of the body, or None if all methods fail
        """
        # Method 1: Direct byte array slicing
        try:
            body = request[body_offset:]
            # Verify it's a proper byte array by checking its type
            # and that buildHttpMessage would accept it
            if body is not None:
                if self._debug:
                    self._add_log("DEBUG", "Body extraction Method 1 (slice) succeeded, len=%d" % len(body))
                return body
        except Exception as e:
            if self._debug:
                self._add_log("DEBUG", "Body extraction Method 1 (slice) failed: %s" % str(e))

        # Method 2: String-based extraction
        try:
            request_str = self._helpers.bytesToString(request)
            body_str = request_str[body_offset:]
            body = self._helpers.stringToBytes(body_str)
            if body is not None:
                if self._debug:
                    self._add_log("DEBUG", "Body extraction Method 2 (string) succeeded, len=%d" % len(body))
                return body
        except Exception as e:
            if self._debug:
                self._add_log("DEBUG", "Body extraction Method 2 (string) failed: %s" % str(e))

        # Method 3: Manual byte copy
        try:
            body_len = len(request) - body_offset
            if body_len <= 0:
                # No body (e.g., GET request) - return empty byte array
                return self._helpers.stringToBytes("")
            body = [request[i] for i in range(body_offset, len(request))]
            # Convert Python list of ints to byte array
            body_bytes = self._helpers.stringToBytes(
                "".join(chr(b & 0xFF) for b in body)
            )
            if self._debug:
                self._add_log("DEBUG", "Body extraction Method 3 (manual) succeeded, len=%d" % len(body_bytes))
            return body_bytes
        except Exception as e:
            if self._debug:
                self._add_log("DEBUG", "Body extraction Method 3 (manual) failed: %s" % str(e))

        return None

    # ============================================================
    # Parameter Stripping Logic
    # ============================================================

    def _strip_parameters(self, request, param_patterns):
        """
        Remove matching parameters from an HTTP request.

        Args:
            request: The raw request bytes (Java byte[])
            param_patterns: List of parameter name patterns to match

        Returns:
            Tuple of (modified_request_bytes, list_of_removed_param_strings)
            If no parameters were removed, returns (original_request, [])
        """
        try:
            # Read matching options from UI
            case_sensitive = self._param_case_sensitive.isSelected()
            regex_mode = self._param_regex_mode.isSelected()
            partial_match = self._param_partial_match.isSelected()

            # Build set of parameter types to strip based on checkboxes
            strip_types = set()
            if self._param_url.isSelected():
                strip_types.add(PARAM_URL)
            if self._param_body.isSelected():
                strip_types.add(PARAM_BODY)
            if self._param_cookie.isSelected():
                strip_types.add(PARAM_COOKIE)
            if self._param_json.isSelected():
                strip_types.add(PARAM_JSON)
            if self._param_xml.isSelected():
                strip_types.add(PARAM_XML)
                strip_types.add(PARAM_XML_ATTR)
            if self._param_multipart.isSelected():
                strip_types.add(PARAM_MULTIPART_ATTR)

            if not strip_types:
                return request, []

            # CRITICAL: Convert Java List to Python list for safe iteration
            request_info = self._helpers.analyzeRequest(request)
            parameters = [p for p in request_info.getParameters()]

            if not parameters:
                return request, []

            # Find parameters that should be removed
            params_to_remove = []
            removed_names = []

            for param in parameters:
                param_name = param.getName()
                param_type = int(param.getType())

                # Check if this parameter type is in the strip set
                if param_type not in strip_types:
                    continue

                if should_match(param_name, param_patterns,
                                case_sensitive, regex_mode, partial_match):
                    params_to_remove.append(param)
                    type_name = PARAM_TYPE_NAMES.get(param_type,
                                                      "Type%d" % param_type)
                    removed_names.append("%s [%s]" % (param_name, type_name))

            # Remove parameters one by one
            modified_request = request
            for param in params_to_remove:
                try:
                    modified_request = self._helpers.removeParameter(
                        modified_request, param
                    )
                except Exception as e:
                    self._add_log(
                        "ERROR",
                        "Failed to remove param '%s': %s" % (param.getName(), str(e))
                    )

            if removed_names:
                return modified_request, removed_names
            else:
                return request, []

        except Exception as e:
            tb = traceback.format_exc()
            self._add_log("ERROR", "_strip_parameters: %s | Traceback: %s" % (str(e), tb))
            return request, []

    # ============================================================
    # ITab Implementation
    # ============================================================

    def getTabCaption(self):
        """Return the tab title displayed in Burp's UI."""
        return "H&P Stripper"

    def getUiComponent(self):
        """Return the root UI component for this tab."""
        return self._panel

    # ============================================================
    # IExtensionStateListener Implementation
    # ============================================================

    def extensionUnloaded(self):
        """Called when the extension is unloaded by the user."""
        self._stop_extension()
        self._add_log("INFO", "Extension unloaded")

    # ============================================================
    # Utility Methods
    # ============================================================

    def _get_tool_name(self, tool_flag):
        """Get the display name for a tool flag constant."""
        for tf, name in TOOL_MAP_ORDERED:
            if tf == tool_flag:
                return name
        return "Tool(%d)" % tool_flag

    # ============================================================
    # Logging
    # ============================================================

    def _add_log(self, level, message):
        """
        Add a log entry. Thread-safe. Updates UI on Swing EDT.

        Args:
            level: Log level string (INFO, HEADER, PARAM, ERROR, DEBUG)
            message: Log message string
        """
        # Skip DEBUG logs unless debug mode is enabled
        if level == "DEBUG" and not self._debug:
            return

        timestamp = time.strftime("%H:%M:%S")
        entry = "[%s] [%s] %s" % (timestamp, level, message)

        with self._log_lock:
            self._log_entries.append(entry)
            # Keep only last 1000 entries to prevent unbounded memory growth
            if len(self._log_entries) > 1000:
                self._log_entries = self._log_entries[-500:]

        SwingUtilities.invokeLater(AppendLogRunnable(self, entry))

    # ============================================================
    # Statistics
    # ============================================================

    def _update_stats_display(self):
        """Update the statistics label (must be called on Swing EDT)."""
        with self._stats_lock:
            h = self._stats_headers_removed
            p = self._stats_params_removed
            r = self._stats_requests_processed
        self._stats_label.setText(
            "Headers removed: %d | Parameters removed: %d | Requests processed: %d"
            % (h, p, r)
        )

    def _reset_stats(self):
        """Reset all statistics counters to zero."""
        with self._stats_lock:
            self._stats_headers_removed = 0
            self._stats_params_removed = 0
            self._stats_requests_processed = 0
        SwingUtilities.invokeLater(UpdateStatsRunnable(self))


# ============================================================
# ActionListener Classes (handle button clicks)
# ============================================================

class StartListener(ActionListener):
    """Handle Start button click - begin processing requests."""
    def __init__(self, ext):
        self._ext = ext

    def actionPerformed(self, event):
        self._ext._start_extension()
        self._ext._add_log("INFO", "Extension STARTED - Processing requests on selected tools")


class StopListener(ActionListener):
    """Handle Stop button click - stop processing requests."""
    def __init__(self, ext):
        self._ext = ext

    def actionPerformed(self, event):
        self._ext._stop_extension()
        self._ext._add_log("INFO", "Extension STOPPED - Requests pass through unmodified")


class ClearLogListener(ActionListener):
    """Handle Clear Log button click."""
    def __init__(self, ext):
        self._ext = ext

    def actionPerformed(self, event):
        with self._ext._log_lock:
            self._ext._log_entries = []
        self._ext._log_text.setText("")


class ResetStatsListener(ActionListener):
    """Handle Reset Stats button click."""
    def __init__(self, ext):
        self._ext = ext

    def actionPerformed(self, event):
        self._ext._reset_stats()


class SelectAllToolsListener(ActionListener):
    """Handle Select All / Deselect All tool checkboxes."""
    def __init__(self, ext, select):
        self._ext = ext
        self._select = select

    def actionPerformed(self, event):
        for cb in self._ext._tool_checkboxes.values():
            cb.setSelected(self._select)


class DebugToggleListener(ActionListener):
    """Handle Debug checkbox toggle."""
    def __init__(self, ext):
        self._ext = ext

    def actionPerformed(self, event):
        self._ext._debug = self._ext._debug_cb.isSelected()
        if self._ext._debug:
            self._ext._add_log("INFO", "Debug mode ENABLED - verbose logging active")
        else:
            self._ext._add_log("INFO", "Debug mode DISABLED")


class TestMatchListener(ActionListener):
    """Handle Test Match button - verify patterns match sample headers/params."""
    def __init__(self, ext, target):
        self._ext = ext
        self._target = target  # "header" or "param"

    def actionPerformed(self, event):
        if self._target == "header":
            patterns = self._ext._get_header_patterns()
            case_sensitive = self._ext._header_case_sensitive.isSelected()
            regex_mode = self._ext._header_regex_mode.isSelected()
            partial_match = self._ext._header_partial_match.isSelected()
            sample_names = ["Authorization", "Cookie", "Accept-Encoding",
                           "X-Forwarded-For", "X-Real-IP", "Host",
                           "User-Agent", "Content-Type", "Referer"]
        else:
            patterns = self._ext._get_param_patterns()
            case_sensitive = self._ext._param_case_sensitive.isSelected()
            regex_mode = self._ext._param_regex_mode.isSelected()
            partial_match = self._ext._param_partial_match.isSelected()
            sample_names = ["session_id", "utm_source", "debug",
                           "tracking_id", "csrf_token", "id",
                           "page", "user_id", "auth_token"]

        self._ext._add_log("INFO", "=== Test Match (%s) ===" % self._target)
        self._ext._add_log("INFO", "Patterns: %s" % str(patterns))
        self._ext._add_log("INFO", "Options: case_sensitive=%s, regex=%s, partial=%s" %
                          (case_sensitive, regex_mode, partial_match))

        if not patterns:
            self._ext._add_log("INFO", "No patterns configured! Enter %s names in the text area first." % self._target)
            return

        matched = []
        not_matched = []
        for name in sample_names:
            if should_match(name, patterns, case_sensitive, regex_mode, partial_match):
                matched.append(name)
            else:
                not_matched.append(name)

        if matched:
            self._ext._add_log("INFO", "MATCHED: %s" % ", ".join(matched))
        else:
            self._ext._add_log("INFO", "NO MATCHES found among sample names")

        if not_matched:
            self._ext._add_log("INFO", "Not matched: %s" % ", ".join(not_matched))


class ImportListener(ActionListener):
    """Handle Import button click - load header/param list from file."""
    def __init__(self, ext, target):
        self._ext = ext
        self._target = target  # "header" or "param"

    def actionPerformed(self, event):
        from javax.swing import JFileChooser
        chooser = JFileChooser()
        chooser.setDialogTitle("Import %s list" % self._target)
        filter = FileNameExtensionFilter("Text files (*.txt)", ["txt"])
        chooser.setFileFilter(filter)
        if chooser.showOpenDialog(self._ext._panel) == JFileChooser.APPROVE_OPTION:
            try:
                selected_file = chooser.getSelectedFile()
                with open(selected_file.getAbsolutePath(), 'r') as fh:
                    content = fh.read()
                if self._target == "header":
                    self._ext._header_text.setText(content)
                else:
                    self._ext._param_text.setText(content)
                self._ext._add_log(
                    "INFO",
                    "Imported %s list from %s" % (self._target, selected_file.getName())
                )
            except Exception as e:
                self._ext._add_log("ERROR", "Import failed: %s" % str(e))


class ExportListener(ActionListener):
    """Handle Export button click - save header/param list to file."""
    def __init__(self, ext, target):
        self._ext = ext
        self._target = target  # "header" or "param"

    def actionPerformed(self, event):
        from javax.swing import JFileChooser
        chooser = JFileChooser()
        chooser.setDialogTitle("Export %s list" % self._target)
        filter = FileNameExtensionFilter("Text files (*.txt)", ["txt"])
        chooser.setFileFilter(filter)
        if chooser.showSaveDialog(self._ext._panel) == JFileChooser.APPROVE_OPTION:
            try:
                selected_file = chooser.getSelectedFile()
                if self._target == "header":
                    content = self._ext._header_text.getText()
                else:
                    content = self._ext._param_text.getText()
                with open(selected_file.getAbsolutePath(), 'w') as fh:
                    fh.write(content)
                self._ext._add_log(
                    "INFO",
                    "Exported %s list to %s" % (self._target, selected_file.getName())
                )
            except Exception as e:
                self._ext._add_log("ERROR", "Export failed: %s" % str(e))


# ============================================================
# Runnable Classes (for Swing EDT thread safety)
# All UI updates MUST happen on the Event Dispatch Thread.
# These Runnable classes are invoked via SwingUtilities.invokeLater().
# ============================================================

class SetStatusRunnable(Runnable):
    """Update the Start/Stop button states and status label on Swing EDT."""
    def __init__(self, ext, is_running):
        self._ext = ext
        self._is_running = is_running

    def run(self):
        if self._is_running:
            self._ext._status_label.setText("RUNNING")
            self._ext._status_label.setForeground(Color(0, 153, 0))  # Green
            self._ext._start_btn.setEnabled(False)
            self._ext._stop_btn.setEnabled(True)
        else:
            self._ext._status_label.setText("STOPPED")
            self._ext._status_label.setForeground(Color(204, 0, 0))  # Dark red
            self._ext._start_btn.setEnabled(True)
            self._ext._stop_btn.setEnabled(False)


class AppendLogRunnable(Runnable):
    """Append a log entry to the log text area on Swing EDT."""
    def __init__(self, ext, entry):
        self._ext = ext
        self._entry = entry

    def run(self):
        current = self._ext._log_text.getText()
        # Truncate if too long to prevent memory issues and slow rendering
        if len(current) > 50000:
            current = current[-25000:]
        self._ext._log_text.setText(current + self._entry + "\n")
        # Auto-scroll to bottom
        try:
            self._ext._log_text.setCaretPosition(
                self._ext._log_text.getDocument().getLength()
            )
        except Exception:
            pass  # Non-critical; don't crash on caret positioning


class UpdateStatsRunnable(Runnable):
    """Update the statistics display label on Swing EDT."""
    def __init__(self, ext):
        self._ext = ext

    def run(self):
        self._ext._update_stats_display()
