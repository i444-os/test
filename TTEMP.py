# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener, ITab
from java.awt import BorderLayout, Font, Color, GridBagLayout, GridBagConstraints, Insets, Dimension
from javax.swing import (JPanel, JLabel, JTextArea, JCheckBox, JButton, JScrollPane, 
                         SwingUtilities, JSplitPane, BorderFactory, BoxLayout, JToggleButton)
from javax.swing.event import DocumentListener
from java.lang import Runnable

class StateManager(object):
    """
    O(1) sets for instantaneous lookups.
    """
    def __init__(self):
        self.is_running = False
        self.active_tools = set()
        self.target_headers = set()
        self.target_params = set()

class UIUpdateListener(DocumentListener):
    """
    Fires ONLY when you type in the text boxes. Pre-computes the target sets.
    """
    def __init__(self, text_area, state_set, is_header=False):
        self.text_area = text_area
        self.state_set = state_set
        self.is_header = is_header

    def update(self):
        text = self.text_area.getText()
        self.state_set.clear()
        # Handles your exact input format: "OStoken,Defaultuserrole"
        for line in text.replace(',', '\n').split('\n'):
            line = line.strip()
            if line:
                # Headers are case-insensitive per RFC. Parameters are case-sensitive!
                self.state_set.add(line.lower() if self.is_header else line)

    def insertUpdate(self, event): self.update()
    def removeUpdate(self, event): self.update()
    def changedUpdate(self, event): self.update()


class BurpExtender(IBurpExtender, IHttpListener, ITab):
    
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks.setExtensionName("Ultimate Header & Param Stripper")
        
        # Initialize ultra-fast state object
        self.state = StateManager()
        
        # THE MISSING IGNITION KEY: TELL BURP TO ROUTE HTTP TRAFFIC TO THIS EXTENSION!
        self.callbacks.registerHttpListener(self)
        
        # Tool Flags Mapping (Burp Constants)
        self.tool_map = {
            "Target": callbacks.TOOL_TARGET,
            "Intruder": callbacks.TOOL_INTRUDER,
            "Extensions": callbacks.TOOL_EXTENDER,
            "Scanner": callbacks.TOOL_SCANNER,
            "Sequencer": callbacks.TOOL_SEQUENCER,
            "Proxy (use with caution)": callbacks.TOOL_PROXY,
            "Repeater": callbacks.TOOL_REPEATER
        }

        # Build UI on the Event Dispatch Thread safely
        SwingUtilities.invokeLater(UIRunnable(self))

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # 1. IMMEDIATE FAIL-FAST CHECKS
        if not messageIsRequest:
            return
        if not self.state.is_running:
            return
        if toolFlag not in self.state.active_tools:
            return

        request_bytes = messageInfo.getRequest()
        modified = False

        # 2. PARAMETER REMOVAL (MUST BE DONE FIRST TO PRESERVE BYTE OFFSETS)
        if self.state.target_params:
            info = self.helpers.analyzeRequest(request_bytes)
            params = info.getParameters()
            for p in params:
                if p.getName() in self.state.target_params:
                    request_bytes = self.helpers.removeParameter(request_bytes, p)
                    modified = True

        # 3. HEADER REMOVAL
        if self.state.target_headers:
            info = self.helpers.analyzeRequest(request_bytes)
            headers = list(info.getHeaders())
            body_offset = info.getBodyOffset()
            
            # Safe slice for Jython byte array conversion
            body = request_bytes[body_offset:]
            
            new_headers = []
            headers_modified = False

            for header in headers:
                # The first line (e.g., GET / HTTP/1.1) doesn't have a colon. Skip it safely.
                if ":" in header:
                    # Extracts the header name and converts to lowercase
                    header_name = header.split(":", 1)[0].strip().lower()
                    
                    # If the user typed "OStoken", it is stored as "ostoken".
                    # The request's "OStoken: value" is checked as "ostoken". THIS WILL MATCH!
                    if header_name in self.state.target_headers:
                        headers_modified = True
                        continue # DESTROY THE HEADER!
                
                new_headers.append(header)

            if headers_modified:
                request_bytes = self.helpers.buildHttpMessage(new_headers, body)
                modified = True

        # 4. UPDATE BURP REQUEST ONLY IF MODIFIED
        if modified:
            messageInfo.setRequest(request_bytes)

    def getTabCaption(self):
        return "Stripper Ultimate"

    def getUiComponent(self):
        return self.main_panel


class UIRunnable(Runnable):
    """
    Swing UI Builder.
    """
    def __init__(self, extender):
        self.extender = extender

    def run(self):
        self.extender.main_panel = JPanel(BorderLayout(10, 10))
        self.extender.main_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        # --- TOP PANEL: MASTER SWITCH ---
        top_panel = JPanel()
        self.toggle_btn = JToggleButton("EXTENSION OFF (CLICK TO START)")
        self.toggle_btn.setFont(Font("Arial", Font.BOLD, 16))
        self.toggle_btn.setForeground(Color.RED)
        self.toggle_btn.setPreferredSize(Dimension(400, 50))
        self.toggle_btn.addActionListener(lambda e: self.toggle_master_switch())
        top_panel.add(self.toggle_btn)
        self.extender.main_panel.add(top_panel, BorderLayout.NORTH)

        # --- LEFT PANEL: TOOL CHECKBOXES ---
        left_panel = JPanel()
        left_panel.setLayout(BoxLayout(left_panel, BoxLayout.Y_AXIS))
        left_panel.setBorder(BorderFactory.createTitledBorder("Active Tools"))
        
        self.checkboxes = {}
        for name, flag in self.extender.tool_map.items():
            cb = JCheckBox(name)
            cb.setFont(Font("Arial", Font.PLAIN, 14))
            if "Proxy" in name:
                cb.setForeground(Color.RED)
            cb.addActionListener(lambda e, f=flag, c=cb: self.update_tools(f, c))
            self.checkboxes[name] = cb
            left_panel.add(cb)
            
        self.extender.main_panel.add(left_panel, BorderLayout.WEST)

        # --- CENTER PANEL: TEXT AREAS ---
        center_panel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.fill = GridBagConstraints.BOTH
        gbc.weightx = 1.0
        gbc.weighty = 0.5
        gbc.insets = Insets(5, 5, 5, 5)

        # Headers Input
        gbc.gridy = 0
        header_label = JLabel("Headers to Remove (Comma or Newline separated):")
        header_label.setFont(Font("Arial", Font.BOLD, 14))
        center_panel.add(header_label, gbc)

        gbc.gridy = 1
        self.header_area = JTextArea(5, 30)
        self.header_area.getDocument().addDocumentListener(
            UIUpdateListener(self.header_area, self.extender.state.target_headers, is_header=True)
        )
        center_panel.add(JScrollPane(self.header_area), gbc)

        # Parameters Input
        gbc.gridy = 2
        param_label = JLabel("Parameters to Remove (Future-Proofed / Comma or Newline separated):")
        param_label.setFont(Font("Arial", Font.BOLD, 14))
        center_panel.add(param_label, gbc)

        gbc.gridy = 3
        self.param_area = JTextArea(5, 30)
        self.param_area.getDocument().addDocumentListener(
            UIUpdateListener(self.param_area, self.extender.state.target_params, is_header=False)
        )
        center_panel.add(JScrollPane(self.param_area), gbc)

        self.extender.main_panel.add(center_panel, BorderLayout.CENTER)
        
        # Register the UI with Burp
        self.extender.callbacks.addSuiteTab(self.extender)

    def toggle_master_switch(self):
        state = self.extender.state
        state.is_running = self.toggle_btn.isSelected()
        if state.is_running:
            self.toggle_btn.setText("EXTENSION RUNNING (CLICK TO STOP)")
            self.toggle_btn.setForeground(Color(0, 153, 0)) # Dark Green
        else:
            self.toggle_btn.setText("EXTENSION OFF (CLICK TO START)")
            self.toggle_btn.setForeground(Color.RED)

    def update_tools(self, flag, checkbox):
        if checkbox.isSelected():
            self.extender.state.active_tools.add(flag)
        else:
            self.extender.state.active_tools.discard(flag)
