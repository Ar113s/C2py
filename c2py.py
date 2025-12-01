import sys
from PyQt6.QtWidgets import QApplication
from src.gui.main_window import MainWindow

def main():
    """Main function to run the C2PY application."""
    app = QApplication(sys.argv)
    
    # Apply enhanced dark theme with professional darker grays
    app.setStyleSheet("""
        QWidget {
            background-color: #1a1a1a;
            color: #e0e0e0;
            font-family: 'Segoe UI', 'Roboto', sans-serif;
            font-size: 9pt;
        }
        QMainWindow {
            background-color: #0f0f0f;
            border: 1px solid #2d2d2d;
        }
        QMenuBar {
            background-color: #1e1e1e;
            color: #ffffff;
            border-bottom: 1px solid #2d2d2d;
            padding: 2px;
        }
        QMenuBar::item {
            background-color: transparent;
            padding: 4px 8px;
            margin: 1px;
        }
        QMenuBar::item:selected {
            background-color: #00d4ff;
            color: #000000;
            border-radius: 2px;
        }
        QMenu {
            background-color: #1e1e1e;
            color: #ffffff;
            border: 1px solid #3d3d3d;
            border-radius: 4px;
        }
        QMenu::item {
            padding: 6px 20px;
            margin: 1px;
        }
        QMenu::item:selected {
            background-color: #00d4ff;
            color: #000000;
            border-radius: 2px;
        }
        QMenu::separator {
            height: 1px;
            background-color: #3d3d3d;
            margin: 2px 0px;
        }
        QPushButton {
            background-color: #2d2d2d;
            border: 1px solid #3d3d3d;
            color: #ffffff;
            padding: 6px 12px;
            border-radius: 3px;
            font-weight: 500;
            min-width: 80px;
        }
        QPushButton:hover {
            background-color: #0078d4;
            border: 1px solid #106ebe;
        }
        QPushButton:pressed {
            background-color: #005a9e;
            border: 1px solid #004578;
        }
        QPushButton:disabled {
            background-color: #1a1a1a;
            color: #666666;
            border: 1px solid #2d2d2d;
        }
        QTabWidget::pane {
            border: 1px solid #2d2d2d;
            background-color: #1a1a1a;
            border-radius: 4px;
        }
        QTabBar::tab {
            background-color: #1a1a1a;
            color: #cccccc;
            border: 1px solid #2d2d2d;
            padding: 8px 16px;
            margin-right: 2px;
            border-top-left-radius: 4px;
            border-top-right-radius: 4px;
        }
        QTabBar::tab:selected {
            background-color: #00d4ff;
            color: #000000;
            border-bottom: 1px solid #00d4ff;
        }
        QTabBar::tab:hover:!selected {
            background-color: #2d2d2d;
        }
        QTableWidget {
            background-color: #0f0f0f;
            color: #ffffff;
            border: 1px solid #2d2d2d;
            border-radius: 4px;
            gridline-color: #2d2d2d;
            selection-background-color: #0078d4;
        }
        QTableWidget::item {
            padding: 4px;
            border-bottom: 1px solid #1a1a1a;
        }
        QTableWidget::item:selected {
            background-color: #0078d4;
            color: #ffffff;
        }
        QHeaderView::section {
            background-color: #1e1e1e;
            color: #ffffff;
            border: 1px solid #2d2d2d;
            padding: 6px;
            font-weight: bold;
        }
        QTextEdit {
            background-color: #0f0f0f;
            color: #ffffff;
            border: 1px solid #2d2d2d;
            border-radius: 4px;
            selection-background-color: #0078d4;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 9pt;
        }
        QLineEdit {
            background-color: #1a1a1a;
            color: #ffffff;
            border: 1px solid #3d3d3d;
            border-radius: 3px;
            padding: 6px;
        }
        QLineEdit:focus {
            border: 1px solid #00d4ff;
        }
        QComboBox {
            background-color: #1a1a1a;
            color: #ffffff;
            border: 1px solid #3d3d3d;
            border-radius: 3px;
            padding: 6px;
        }
        QComboBox::drop-down {
            border: none;
            width: 20px;
        }
        QComboBox::down-arrow {
            border-left: 5px solid transparent;
            border-right: 5px solid transparent;
            border-top: 5px solid #ffffff;
            margin-right: 5px;
        }
        QComboBox QAbstractItemView {
            background-color: #1e1e1e;
            color: #ffffff;
            border: 1px solid #3d3d3d;
            selection-background-color: #0078d4;
        }
        QScrollBar:vertical {
            background-color: #1a1a1a;
            border: none;
            width: 12px;
            border-radius: 6px;
        }
        QScrollBar::handle:vertical {
            background-color: #3d3d3d;
            border-radius: 6px;
            margin: 2px;
        }
        QScrollBar::handle:vertical:hover {
            background-color: #555555;
        }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
            height: 0px;
        }
        QStatusBar {
            background-color: #1e1e1e;
            color: #cccccc;
            border-top: 1px solid #2d2d2d;
        }
        QSplitter::handle {
            background-color: #2d2d2d;
        }
        QSplitter::handle:horizontal {
            width: 3px;
        }
        QSplitter::handle:vertical {
            height: 3px;
        }
        QProgressBar {
            background-color: #1a1a1a;
            border: 1px solid #2d2d2d;
            border-radius: 3px;
            text-align: center;
            color: #ffffff;
        }
        QProgressBar::chunk {
            background-color: #00d4ff;
            border-radius: 2px;
        }
        QGroupBox {
            border: 2px solid #2d2d2d;
            border-radius: 5px;
            margin-top: 10px;
            padding-top: 10px;
            background-color: #1a1a1a;
            font-weight: bold;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 5px 0 5px;
            color: #00d4ff;
        }
    """)
    
    # Set the application icon with fallback options
    try:
        from PyQt6.QtGui import QIcon
        import os
        
        # Try different icon paths in order of preference
        icon_paths = [
            'img/c2py_logo.ico',
            'img/logo.ico', 
            'img/c2py_logo.png',
            'img/logo.png'
        ]
        
        for icon_path in icon_paths:
            if os.path.exists(icon_path):
                app.setWindowIcon(QIcon(icon_path))
                break
    except:
        pass
    
    # Create the main window
    window = MainWindow()
    window.show()
    
    # Run the application
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
