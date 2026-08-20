import React, { useState, useEffect } from 'react';
import { Outlet, NavLink, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useWebSocket } from '../context/WebSocketContext';
import { Menu, X, LogOut, Settings, Activity, Database, Shield, Terminal, Users, Globe, ChevronLeft, ChevronRight } from 'lucide-react';
import './Sidebar.css';

const navigation = [
  { name: 'Dashboard', href: '/', icon: Activity },
  { name: 'Assessments', href: '/assessments', icon: Shield },
  { name: 'Campaigns', href: '/campaigns', icon: Globe },
  { name: 'Skills', href: '/skills', icon: Terminal },
  { name: 'Memory', href: '/memory', icon: Database },
  { name: 'Settings', href: '/settings', icon: Settings },
];

export default function Layout() {
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const { user, logout } = useAuth();
  const { connected } = useWebSocket();
  const navigate = useNavigate();
  const location = useLocation();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <div className="layout">
      {/* Mobile menu button */}
      <button 
        className="mobile-menu-btn" 
        onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
        aria-label="Toggle menu"
      >
        <Menu size={24} />
      </button>

      {/* Sidebar */}
      <aside className={`sidebar ${sidebarOpen ? 'open' : 'collapsed'} ${mobileMenuOpen ? 'mobile-open' : ''}`}>
        <div className="sidebar-header">
          <div className="logo">
            <span className="logo-icon">🦞</span>
            <span className={`logo-text ${sidebarOpen ? '' : 'hidden'}`}>ERREETOOL</span>
          </div>
          <button 
            className="sidebar-toggle" 
            onClick={() => setSidebarOpen(!sidebarOpen)}
            aria-label={sidebarOpen ? 'Collapse sidebar' : 'Expand sidebar'}
          >
            <ChevronLeft size={20} />
          </button>
        </div>

        <nav className="sidebar-nav">
          <ul>
            {navigation.map((item) => {
              const isActive = location.pathname === item.href || 
                (item.href !== '/' && location.pathname.startsWith(item.href));
              const Icon = item.icon;
              return (
                <li key={item.href}>
                  <NavLink
                    to={item.href}
                    className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
                    onClick={() => window.innerWidth < 768 && setMobileMenuOpen(false)}
                  >
                    <Icon size={20} />
                    <span className={sidebarOpen ? '' : 'hidden'}>{item.name}</span>
                  </NavLink>
                </li>
              );
            })}
          </ul>
        </nav>

        <div className="sidebar-footer">
          <div className="connection-status">
            <span className={`status-indicator ${connected ? 'connected' : 'disconnected'}`}></span>
            <span className="status-text">{connected ? 'Connected' : 'Disconnected'}</span>
          </div>
          <div className="user-info">
            <div className="user-avatar">
              {user?.username?.charAt(0).toUpperCase() || 'U'}
            </div>
            <div className="user-details">
              <span className="username">{user?.username || 'User'}</span>
              <span className="role">{user?.role || 'analyst'}</span>
            </div>
            <button className="logout-btn" onClick={logout} title="Logout">
              <LogOut size={18} />
            </button>
          </div>
        </div>
      </nav>

      {/* Mobile overlay */}
      {mobileMenuOpen && (
        <div className="mobile-overlay" onClick={() => setMobileMenuOpen(false)} />
      }>

      {/* Main content */}
      <main className="main-content">
        <Outlet />
      </main>

      {/* Mobile sidebar toggle */}
      <button 
        className="mobile-sidebar-toggle" 
        onClick={() => setMobileMenuOpen(true)}
        aria-label="Open menu"
      >
        <Menu size={24} />
      </button>
    </>
  );
}

export default Layout;