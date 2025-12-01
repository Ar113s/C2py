#!/usr/bin/env python3
"""
Icon System Module
Icon management and button styling for C2PY Framework
"""

from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *
import os

class IconSystem:
    def __init__(self):
        self.icon_cache = {}
        self.icon_path = os.path.join(os.path.dirname(__file__), "icons")
        
    def get_icon(self, name):
        """Get icon by name"""
        if name in self.icon_cache:
            return self.icon_cache[name]
        
        # Create simple colored icons if files don't exist
        icon = self.create_colored_icon(name)
        self.icon_cache[name] = icon
        return icon
    
    def create_colored_icon(self, name):
        """Create a simple colored icon"""
        pixmap = QPixmap(16, 16)
        
        # Color mapping for different icon types
        colors = {
            "start": "#00ff00",      # Green
            "stop": "#ff0000",       # Red
            "settings": "#ffff00",   # Yellow
            "shells": "#00ffff",     # Cyan
            "agents": "#ff00ff",     # Magenta
            "logs": "#ffffff",       # White
            "exit": "#ff4444",       # Light Red
            "info": "#4444ff",       # Blue
            "warning": "#ffaa00",    # Orange
            "error": "#ff0000",      # Red
            "success": "#00ff00",    # Green
            "default": "#888888"     # Gray
        }
        
        color = colors.get(name.lower(), colors["default"])
        pixmap.fill(QColor(color))
        
        return QIcon(pixmap)

# Global icon system instance
_icon_system = IconSystem()

def get_icon(name):
    """Get icon by name (global function)"""
    return _icon_system.get_icon(name)

def setup_button_icon(button, icon_name):
    """Setup icon for button"""
    icon = get_icon(icon_name)
    button.setIcon(icon)
    button.setIconSize(QSize(16, 16))

def setup_status_icon(widget, status):
    """Setup status icon for widget"""
    icon = get_icon(status)
    if hasattr(widget, 'setIcon'):
        widget.setIcon(icon)
