# -*- coding: utf-8 -*-
"""
Auto-Auth Session Manager for Burp Suite (Jython 2.7.4)
Author: Built for benchmarking - production grade
"""

from burp import (IBurpExtender, ITab, IHttpListener,
                  ISessionHandlingAction, IExtensionStateListener)
from javax.swing import (JPanel, JLabel, JTextField, JTextArea, JButton,
                         JCheckBox, JScrollPane, BoxLayout, JSeparator,
                         BorderFactory, SwingUtilities, JOptionPane)
from javax.swing import SwingConstants
from java.awt import (GridBagLayout, GridBagConstraints, Insets, Dimension,
                      Color, Font)
from java.awt.event import ActionListener
from java.util.concurrent.locks import ReentrantLock
from java.net import URL
import base64
import json
import time
import re

EXT_NAME = "Auto-Auth Session Manager"
VERSION  = "1.0.0"

# Burp tool flag constants (from IBurpExtenderCallbacks)
TOOL_FLAGS = [
    ("Target",   0x00000010),
    ("Proxy",    0x00000020),
    ("Spider",   0x00000040),
    ("Scanner",  0x00000080),
    ("Intruder", 0x00000100),
    ("Repeater", 0x00000200),
    ("Sequencer",0x00000400),
    ("Extender", 0x00000800),
]
DEFAULT_ENABLED_TOOLS = {"Target","Intruder","Scanner","Sequencer",
                         "Repeater","Extender"}   # Proxy OFF by default


class BurpExtender(IBurpExtender, ITab, IHttpListener,
                   ISessionHandlingAction, IExtensionStateListener):

    # ---------- Burp entry ----------
    def registerExtenderCallbacks(self, callbacks):
        self._cb      = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout  = callbacks.getStdout()

        callbacks.setExtensionName(EXT_NAME)

        # State
        self._lock        = ReentrantLock()
        self._jwt         = None       # cached JWT
        self._jwt_exp     = 0          # epoch
        self._jsessionid  = None       # cached JSESSIONID
        self._running     = False      # master switch
        self._tool_flags  = {}         # name -> JCheckBox

        self._load_settings()
        self._build_ui()

        callbacks.registerHttpListener(self)
        callbacks.registerSessionHandlingAction(self)
        callbacks.registerExt
