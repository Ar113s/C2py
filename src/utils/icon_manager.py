"""
Professional Icon Manager for C2PY
Provides corporate-style icons to replace emojis throughout the application
"""

from PyQt6.QtGui import QIcon, QPixmap, QPainter, QBrush, QColor
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtSvg import QSvgRenderer
import os

class IconManager:
    """Manages professional icons for the C2 framework"""
    
    def __init__(self):
        self.icon_cache = {}
        self.icon_color = QColor("#00d4ff")  # Cyan accent color
        self.secondary_color = QColor("#ffffff")  # White
        self.danger_color = QColor("#ff4444")  # Red
        self.success_color = QColor("#00ff88")  # Green
        self.warning_color = QColor("#ffaa00")  # Orange
        
    def create_text_icon(self, text, size=16, color=None):
        """Create a text-based icon"""
        if color is None:
            color = self.icon_color
            
        pixmap = QPixmap(size, size)
        pixmap.fill(Qt.GlobalColor.transparent)
        
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(color)
        painter.drawText(pixmap.rect(), Qt.AlignmentFlag.AlignCenter, text)
        painter.end()
        
        return QIcon(pixmap)
    
    def create_shape_icon(self, shape_type, size=16, color=None, fill=True):
        """Create geometric shape icons"""
        if color is None:
            color = self.icon_color
            
        pixmap = QPixmap(size, size)
        pixmap.fill(Qt.GlobalColor.transparent)
        
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        if fill:
            painter.setBrush(QBrush(color))
        else:
            painter.setPen(color)
        
        margin = 2
        rect = pixmap.rect().adjusted(margin, margin, -margin, -margin)
        
        if shape_type == "circle":
            painter.drawEllipse(rect)
        elif shape_type == "square":
            painter.drawRect(rect)
        elif shape_type == "triangle":
            points = [
                rect.topLeft() + rect.center() - rect.topLeft(),
                rect.bottomLeft(),
                rect.bottomRight()
            ]
            painter.drawPolygon(points)
        elif shape_type == "diamond":
            points = [
                rect.center() + (0, -rect.height()//2),
                rect.center() + (rect.width()//2, 0),
                rect.center() + (0, rect.height()//2),
                rect.center() + (-rect.width()//2, 0)
            ]
            painter.drawPolygon(points)
        
        painter.end()
        return QIcon(pixmap)
    
    def get_agent_icon(self, status="online"):
        """Get agent status icon"""
        if status == "online":
            return self.create_shape_icon("circle", color=self.success_color)
        elif status == "offline":
            return self.create_shape_icon("circle", color=self.danger_color)
        elif status == "unknown":
            return self.create_shape_icon("circle", color=self.warning_color)
        else:
            return self.create_shape_icon("circle", color=self.icon_color)
    
    def get_command_icon(self, command_type):
        """Get icon for command types"""
        icons = {
            "system": self.create_text_icon("SYS", color=self.icon_color),
            "network": self.create_text_icon("NET", color=self.icon_color),
            "file": self.create_text_icon("FILE", color=self.icon_color),
            "process": self.create_text_icon("PROC", color=self.icon_color),
            "registry": self.create_text_icon("REG", color=self.icon_color),
            "service": self.create_text_icon("SVC", color=self.icon_color),
            "payload": self.create_text_icon("PAY", color=self.warning_color),
            "download": self.create_text_icon("DL", color=self.success_color),
            "upload": self.create_text_icon("UP", color=self.success_color),
            "execute": self.create_text_icon("EXE", color=self.danger_color),
            "monitor": self.create_text_icon("MON", color=self.icon_color),
            "persist": self.create_text_icon("PER", color=self.warning_color),
            "elevate": self.create_text_icon("ELEV", color=self.danger_color),
            "lateral": self.create_text_icon("LAT", color=self.warning_color),
            "stealth": self.create_text_icon("STL", color=self.icon_color)
        }
        return icons.get(command_type, self.create_text_icon("CMD"))
    
    def get_lolbas_icon(self, technique_type):
        """Get icon for LOLBAS techniques"""
        icons = {
            "execution": self.create_text_icon("EXEC", color=self.danger_color),
            "persistence": self.create_text_icon("PERS", color=self.warning_color),
            "privilege_escalation": self.create_text_icon("PRIV", color=self.danger_color),
            "defense_evasion": self.create_text_icon("EVA", color=self.icon_color),
            "credential_access": self.create_text_icon("CRED", color=self.warning_color),
            "discovery": self.create_text_icon("DISC", color=self.icon_color),
            "lateral_movement": self.create_text_icon("LAT", color=self.warning_color),
            "collection": self.create_text_icon("COL", color=self.icon_color),
            "exfiltration": self.create_text_icon("EXFIL", color=self.success_color)
        }
        return icons.get(technique_type, self.create_text_icon("LOLB"))
    
    def get_payload_quality_icon(self, quality_level):
        """Get icon for payload quality levels"""
        if quality_level >= 90:
            return self.create_text_icon("A+", color=self.success_color)
        elif quality_level >= 80:
            return self.create_text_icon("A", color=self.success_color)
        elif quality_level >= 70:
            return self.create_text_icon("B", color=self.icon_color)
        elif quality_level >= 60:
            return self.create_text_icon("C", color=self.warning_color)
        else:
            return self.create_text_icon("F", color=self.danger_color)
    
    def get_menu_icon(self, menu_type):
        """Get icon for menu items"""
        icons = {
            "connect": self.create_text_icon("CON", color=self.success_color),
            "disconnect": self.create_text_icon("DIS", color=self.danger_color),
            "terminal": self.create_text_icon("TERM", color=self.icon_color),
            "file_manager": self.create_text_icon("FM", color=self.icon_color),
            "process_monitor": self.create_text_icon("PM", color=self.icon_color),
            "screenshot": self.create_text_icon("SCR", color=self.icon_color),
            "keylogger": self.create_text_icon("KEY", color=self.warning_color),
            "webcam": self.create_text_icon("CAM", color=self.warning_color),
            "audio": self.create_text_icon("AUD", color=self.warning_color),
            "clipboard": self.create_text_icon("CLIP", color=self.icon_color),
            "registry": self.create_text_icon("REG", color=self.icon_color),
            "services": self.create_text_icon("SVC", color=self.icon_color),
            "network": self.create_text_icon("NET", color=self.icon_color),
            "system_info": self.create_text_icon("INFO", color=self.icon_color),
            "credentials": self.create_text_icon("CRED", color=self.warning_color),
            "privilege_escalation": self.create_text_icon("PRIV", color=self.danger_color),
            "persistence": self.create_text_icon("PERS", color=self.warning_color),
            "lateral_movement": self.create_text_icon("LAT", color=self.warning_color),
            "data_exfiltration": self.create_text_icon("EXFIL", color=self.success_color),
            "anti_forensics": self.create_text_icon("AF", color=self.icon_color),
            "remove": self.create_text_icon("DEL", color=self.danger_color),
            "refresh": self.create_text_icon("REF", color=self.icon_color),
            "properties": self.create_text_icon("PROP", color=self.icon_color)
        }
        return icons.get(menu_type, self.create_text_icon("•"))

# Global icon manager instance
icon_manager = IconManager()
