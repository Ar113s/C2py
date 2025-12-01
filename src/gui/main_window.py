
import sys
from PyQt6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QTabWidget, QSplitter, QStatusBar, QLabel, QApplication)
from PyQt6.QtGui import QIcon, QAction, QScreen
from PyQt6.QtCore import Qt

from .views.listener_manager_view import ListenerManagerView
from .views.agent_manager_view import AgentManagerView
from .views.loot_manager_view import LootManagerView
from .views.payload_generator_view import PayloadGeneratorView
from ..utils.icon_system import get_icon
from .dialogs.listener_config_dialog import ListenerConfigDialog
from ..core.c2_server import C2Server

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("C2PY Framework")
        
        # Set window icon with fallback options
        try:
            import os
            icon_paths = [
                "img/c2py_logo.ico",
                "img/logo.ico",
                "img/c2py_logo.png", 
                "img/logo.png"
            ]
            
            for icon_path in icon_paths:
                if os.path.exists(icon_path):
                    self.setWindowIcon(QIcon(icon_path))
                    break
        except:
            pass
        
        # Setup responsive window sizing
        self.setup_responsive_window()

        # Initialize C2 Server
        self.c2_server = C2Server()
        self.c2_server.agent_connected.connect(self.on_agent_connected)
        self.c2_server.listener_started.connect(self.on_listener_started)
        self.c2_server.agent_disconnected.connect(self.on_agent_disconnected)
        self.c2_server.command_response.connect(self.on_command_response)

        self._create_actions()
        self._create_toolbars()
        self._create_central_widget()
        self._create_status_bar()
    
    def setup_responsive_window(self):
        """Setup responsive window sizing based on screen resolution"""
        screen = QApplication.primaryScreen()
        if screen:
            screen_geometry = screen.availableGeometry()
            
            # Set window to 90% of screen size
            width = int(screen_geometry.width() * 0.9)
            height = int(screen_geometry.height() * 0.9)
            
            # Center the window
            x = screen_geometry.x() + (screen_geometry.width() - width) // 2
            y = screen_geometry.y() + (screen_geometry.height() - height) // 2
            
            self.setGeometry(x, y, width, height)
            
            # Set minimum size (60% of screen)
            min_width = int(screen_geometry.width() * 0.6)
            min_height = int(screen_geometry.height() * 0.6)
            self.setMinimumSize(min_width, min_height)
        else:
            # Fallback for systems without screen detection
            self.setGeometry(100, 100, 1600, 900)
            self.setMinimumSize(1200, 700)

    def _create_actions(self):
        self.new_listener_action = QAction(QIcon(), "New Listener", self) # Placeholder for icon
        self.new_listener_action.triggered.connect(self.open_new_listener_dialog)
        
        self.exit_action = QAction(QIcon(), "Exit", self) # Placeholder for icon
        self.exit_action.triggered.connect(self.close)

    def _create_toolbars(self):
        toolbar = self.addToolBar("Main Toolbar")
        toolbar.setMovable(False)
        toolbar.addAction(self.new_listener_action)
        toolbar.addSeparator()
        toolbar.addAction(self.exit_action)

    def _create_central_widget(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Main splitter
        main_splitter = QSplitter(Qt.Orientation.Vertical)
        main_layout.addWidget(main_splitter)

        # Top part with listeners and agents
        top_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        self.listener_manager_view = ListenerManagerView()
        self.agent_manager_view = AgentManagerView(c2_server=self.c2_server)

        # Connect C2 server to agent manager
        self.agent_manager_view.set_c2_server(self.c2_server)

        top_splitter.addWidget(self.listener_manager_view)
        top_splitter.addWidget(self.agent_manager_view)
        top_splitter.setSizes([400, 1200])

        # Bottom part with tabs
        bottom_tabs = QTabWidget()
        self.loot_manager_view = LootManagerView()
        self.payload_generator_view = PayloadGeneratorView()
        
        bottom_tabs.addTab(self.loot_manager_view, "Loot")
        bottom_tabs.addTab(self.payload_generator_view, "Payload Generator")
        
        main_splitter.addWidget(top_splitter)
        main_splitter.addWidget(bottom_tabs)
        main_splitter.setSizes([600, 300])

    def _create_status_bar(self):
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")

    def open_new_listener_dialog(self):
        dialog = ListenerConfigDialog(self)
        if dialog.exec():
            config = dialog.get_config()
            self.listener_manager_view.add_listener(config)
            # Start the actual listener backend
            self.c2_server.start_listener(config)
            print(f"Starting listener with config: {config}")

    def on_agent_connected(self, agent_info):
        """Handle new agent connection"""
        self.agent_manager_view.add_agent(agent_info)
        self.status_bar.showMessage(f"Agent {agent_info['id']} connected from {agent_info['hostname']}")
        print(f"Agent connected: {agent_info}")

    def on_agent_disconnected(self, agent_id):
        """Handle agent disconnection"""
        self.agent_manager_view.remove_agent_by_id(agent_id)
        self.status_bar.showMessage(f"Agent {agent_id} disconnected")
        print(f"Agent disconnected: {agent_id}")

    def on_command_response(self, agent_id, command, response):
        """Handle command response from agent"""
        # Forward to agent manager view with enhanced data
        self.agent_manager_view.handle_command_response(agent_id, command, response)

    def on_listener_started(self, config):
        """Handle listener started"""
        self.status_bar.showMessage(f"Listener '{config['name']}' started on {config['host']}:{config['port']}")
        print(f"Listener started: {config}")

    def closeEvent(self, event):
        """Handle application close"""
        try:
            self.c2_server.stop_all()
        except:
            pass
        event.accept()
