from burp import IBurpExtender, ITab
from javax.swing import JPanel, JTextArea, JScrollPane, JButton, JLabel, JTextField, JSplitPane, BoxLayout, Box, JComboBox
from java.awt import BorderLayout, GridLayout, Dimension, Font, Color
from java.awt.event import ActionListener
import urllib
import base64
import hashlib
import binascii
import re

class BurpExtender(IBurpExtender, ITab, ActionListener):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Enhanced Decoder")
        
        # Create UI
        self._panel = JPanel(BorderLayout())
        
        # Top panel with input
        topPanel = JPanel(BorderLayout())
        topPanel.add(JLabel("Input Text:"), BorderLayout.NORTH)
        
        self._inputArea = JTextArea(5, 50)
        self._inputArea.setLineWrap(True)
        self._inputArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        inputScroll = JScrollPane(self._inputArea)
        topPanel.add(inputScroll, BorderLayout.CENTER)
        
        # Button panel
        buttonPanel = JPanel()
        self._encodeBtn = JButton("Encode All")
        self._encodeBtn.addActionListener(self)
        self._decodeBtn = JButton("Decode All")
        self._decodeBtn.addActionListener(self)
        self._clearBtn = JButton("Clear")
        self._clearBtn.addActionListener(self)
        
        buttonPanel.add(self._encodeBtn)
        buttonPanel.add(self._decodeBtn)
        buttonPanel.add(self._clearBtn)
        topPanel.add(buttonPanel, BorderLayout.SOUTH)
        
        # Output area
        bottomPanel = JPanel(BorderLayout())
        bottomPanel.add(JLabel("Results:"), BorderLayout.NORTH)
        
        self._outputArea = JTextArea(20, 50)
        self._outputArea.setLineWrap(True)
        self._outputArea.setEditable(False)
        self._outputArea.setFont(Font("Monospaced", Font.PLAIN, 11))
        outputScroll = JScrollPane(self._outputArea)
        bottomPanel.add(outputScroll, BorderLayout.CENTER)
        
        # Split pane
        splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT, topPanel, bottomPanel)
        splitPane.setDividerLocation(200)
        self._panel.add(splitPane)
        
        # Add tab
        callbacks.addSuiteTab(self)
        
        print("Enhanced Decoder Extension Loaded!")
    
    def getTabCaption(self):
        return "Enhanced Decoder"
    
    def getUiComponent(self):
        return self._panel
    
    def actionPerformed(self, event):
        if event.getSource() == self._encodeBtn:
            self.encodeAll()
        elif event.getSource() == self._decodeBtn:
            self.decodeAll()
        elif event.getSource() == self._clearBtn:
            self._inputArea.setText("")
            self._outputArea.setText("")
    
    def encodeAll(self):
        text = self._inputArea.getText()
        if not text:
            self._outputArea.setText("Please enter text to encode")
            return
        
        output = []
        output.append("=== ENCODING RESULTS ===\n")
        output.append("Original: {}\n".format(text))
        
        # URL Encodings
        output.append("\n--- URL ENCODINGS ---")
        output.append("URL Encode (Special Only): {}".format(self.url_encode_special_only(text)))
        output.append("URL Encode (All): {}".format(self.url_encode_all(text)))
        output.append("URL Encode (Space as +): {}".format(self.url_encode_standard(text)))
        output.append("Double URL Encode: {}".format(self.double_url_encode(text)))
        
        # Unicode & HTML
        output.append("\n--- UNICODE & HTML ---")
        output.append("Unicode Escape (\\uXXXX): {}".format(self.unicode_escape(text)))
        output.append("HTML Entity (Decimal): {}".format(self.html_entity_encode(text)))
        output.append("HTML Entity (Named): {}".format(self.html_entity_encode_named(text)))
        
        # Base64
        output.append("\n--- BASE64 ---")
        output.append("Base64 Standard: {}".format(self.base64_encode(text)))
        output.append("Base64 URL Safe: {}".format(self.base64_url_safe_encode(text)))
        
        # Hex
        output.append("\n--- HEX ---")
        output.append("Hex (\\x prefix): {}".format(self.hex_encode_slash_x(text)))
        output.append("Hex (0x prefix): {}".format(self.hex_encode_0x(text)))
        output.append("Hex (plain): {}".format(self.hex_encode_plain(text)))
        
        # Other
        output.append("\n--- OTHER ---")
        output.append("Binary: {}".format(self.to_binary(text)))
        output.append("ROT13: {}".format(self.rot13(text)))
        output.append("Reverse: {}".format(self.reverse(text)))
        
        # Hashes
        output.append("\n--- HASHES ---")
        output.append("MD5: {}".format(self.md5_hash(text)))
        output.append("SHA-1: {}".format(self.sha1_hash(text)))
        output.append("SHA-256: {}".format(self.sha256_hash(text)))
        
        self._outputArea.setText("\n".join(output))
    
    def decodeAll(self):
        text = self._inputArea.getText()
        if not text:
            self._outputArea.setText("Please enter text to decode")
            return
        
        output = []
        output.append("=== DECODING RESULTS ===\n")
        output.append("Original: {}\n".format(text))
        
        # Try various decodings
        output.append("--- ATTEMPTED DECODINGS ---")
        
        # URL Decode
        try:
            output.append("URL Decode: {}".format(urllib.unquote(text)))
        except:
            output.append("URL Decode: [Failed]")
        
        # HTML Decode
        try:
            output.append("HTML Decode: {}".format(self.html_decode(text)))
        except:
            output.append("HTML Decode: [Failed]")
        
        # Base64 Decode
        try:
            output.append("Base64 Decode: {}".format(base64.b64decode(text)))
        except:
            output.append("Base64 Decode: [Failed - not valid base64]")
        
        # Hex Decode
        try:
            cleaned = re.sub(r'[^0-9a-fA-F]', '', text)
            output.append("Hex Decode: {}".format(binascii.unhexlify(cleaned)))
        except:
            output.append("Hex Decode: [Failed - not valid hex]")
        
        # ROT13
        output.append("ROT13: {}".format(self.rot13(text)))
        
        # Reverse
        output.append("Reverse: {}".format(self.reverse(text)))
        
        self._outputArea.setText("\n".join(output))
    
    # Encoding methods
    def url_encode_special_only(self, text):
        result = []
        for c in text:
            if c.isalnum() or c in '-_.~':
                result.append(c)
            else:
                result.append(urllib.quote(c))
        return ''.join(result)
    
    def url_encode_all(self, text):
        return ''.join(['%{:02X}'.format(ord(c)) for c in text])
    
    def url_encode_standard(self, text):
        return urllib.quote_plus(text)
    
    def double_url_encode(self, text):
        first = self.url_encode_special_only(text)
        return self.url_encode_all(first)
    
    def unicode_escape(self, text):
        result = []
        for c in text:
            if ord(c) > 127 or c in '"\\' or ord(c) < 32:
                result.append('\\u{:04x}'.format(ord(c)))
            else:
                result.append(c)
        return ''.join(result)
    
    def html_entity_encode(self, text):
        result = []
        for c in text:
            if ord(c) > 127 or c in '<>&"\'':
                result.append('&#{};'.format(ord(c)))
            else:
                result.append(c)
        return ''.join(result)
    
    def html_entity_encode_named(self, text):
        result = text.replace('&', '&amp;')
        result = result.replace('<', '&lt;')
        result = result.replace('>', '&gt;')
        result = result.replace('"', '&quot;')
        result = result.replace("'", '&#39;')
        return result
    
    def html_decode(self, text):
        result = re.sub(r'&#(\d+);', lambda m: chr(int(m.group(1))), text)
        result = result.replace('&lt;', '<')
        result = result.replace('&gt;', '>')
        result = result.replace('&quot;', '"')
        result = result.replace('&#39;', "'")
        result = result.replace('&amp;', '&')
        return result
    
    def base64_encode(self, text):
        return base64.b64encode(text).decode('utf-8')
    
    def base64_url_safe_encode(self, text):
        return base64.urlsafe_b64encode(text).rstrip('=').decode('utf-8')
    
    def hex_encode_slash_x(self, text):
        return ''.join(['\\x{:02x}'.format(ord(c)) for c in text])
    
    def hex_encode_0x(self, text):
        return ' '.join(['0x{:02x}'.format(ord(c)) for c in text])
    
    def hex_encode_plain(self, text):
        return ''.join(['{:02x}'.format(ord(c)) for c in text])
    
    def to_binary(self, text):
        return ' '.join([format(ord(c), '08b') for c in text])
    
    def rot13(self, text):
        result = []
        for c in text:
            if 'a' <= c <= 'z':
                result.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
            elif 'A' <= c <= 'Z':
                result.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
            else:
                result.append(c)
        return ''.join(result)
    
    def reverse(self, text):
        return text[::-1]
    
    def md5_hash(self, text):
        return hashlib.md5(text).hexdigest()
    
    def sha1_hash(self, text):
        return hashlib.sha1(text).hexdigest()
    
    def sha256_hash(self, text):
        return hashlib.sha256(text).hexdigest()
