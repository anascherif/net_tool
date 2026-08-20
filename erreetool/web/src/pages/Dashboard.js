import React, { useState, useEffect, useCallback } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import axios from 'axios';
import { Activity, Shield, Database, Globe, TrendingUp, AlertTriangle, Clock, CheckCircle, XCircle, RefreshCw, Plus, Search, Filter, Download, Eye, Edit, Trash2, Zap } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';

function Dashboard() {
  const [stats, setStats] = useState({
    totalAssessments: 0,
    runningAssessments: 0,
    completedToday: 0,
    criticalFindings: 0,
    totalSkills: 0,
    memorySessions: 0,
  });
  const [recentAssessments, setRecentAssessments] = useState([]);
  const [recentActivity, setRecentActivity] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchData = useCallback(async () => {
    try {
      setLoading(true);
      const [statsRes, assessmentsRes, activityRes] = await Promise.all([
        axios.get('/api/v1/assessments/stats'),
        axios.get('/api/v1/assessments?limit=5&sort=-created_at'),
        axios.get('/api/v1/activity/recent?limit=10'),
      ]);
      
      setStats(statsRes.data);
      setRecentAssessments(assessmentsRes.data.assessments || []);
      setRecentActivity(activityRes.data.activities || []);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to load dashboard');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const getStatusBadge = (status) => {
    const badges = {
      pending: 'info',
      running: 'warning',
      completed: 'success',
      failed: 'error',
      cancelled: 'neutral',
    };
    return badges[status] || 'neutral';
  };

  const getStatusIcon = (status) => {
    const icons = {
      pending: Clock,
      running: Zap,
      completed: CheckCircle,
      failed: XCircle,
      cancelled: AlertTriangle,
    };
    return icons[status] || Clock;
  };

  if (loading) {
    return (
      <div className="dashboard">
        <div className="loading">
          <div className="spinner"></div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="dashboard">
        <div className="empty-state">
          <AlertTriangle size={64} />
          <h3>Failed to load dashboard</h3>
          <p>{error}</p>
          <button className="btn btn-primary" onClick={fetchData}>
            <RefreshCw size={16} /> Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="dashboard">
      <div className="page-header">
        <div>
          <h1 className="page-title">Dashboard</h1>
          <p className="page-subtitle">Overview of your penetration testing activities</p>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button className="btn btn-secondary" onClick={fetchData}>
            <RefreshCw size={16} /> Refresh
          </button>
          <Link to="/assessments/new" className="btn btn-primary">
            <Plus size={16} /> New Assessment
          </Link>
        </div>
      </div>

      <div className="stat-grid">
        <div className="stat-card">
          <div className="stat-value">{stats.totalAssessments || 0}</div>
          <div className="stat-label">Total Assessments</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{stats.runningAssessments || 0}</div>
          <div className="stat-label">Running Now</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{stats.completedToday || 0}</div>
          <div className="stat-label">Completed Today</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{stats.criticalFindings || 0}</div>
          <div className="stat-label">Critical Findings</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{stats.totalSkills || 0}</div>
          <div className="stat-label">Available Skills</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{stats.memorySessions || 0}</div>
          <div className="stat-label">Memory Sessions</div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Recent Assessments</h3>
            <Link to="/assessments" className="btn btn-secondary" style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}>
              View All
            </Link>
          </div>
          {recentAssessments.length === 0 ? (
            <div className="empty-state" style={{ padding: '2rem' }}>
              <Shield size={48} />
              <h4>No assessments yet</h3>
              <p>Start your first assessment to see results here</p>
              <Link to="/assessments/new" className="btn btn-primary" style={{ marginTop: '1rem' }}>
                <Plus size={16} /> Create Assessment
              </Link>
            </div>
          ) : (
            <div className="table-container">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Target</th>
                    <th>Status</th>
                    <th>Engine</th>
                    <th>Progress</th>
                    <th>Created</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {recentAssessments.map((assessment) => {
                    const StatusIcon = getStatusIcon(assessment.status);
                    return (
                      <tr key={assessment.assessment_id}>
                        <td>
                          <Link to={`/assessments/${assessment.assessment_id}`} style={{ color: 'inherit', textDecoration: 'none' }}>
                            <code>{assessment.target}</code>
                          </Link>
                        </td>
                        <td>
                          <span className={`badge badge-${getStatusBadge(assessment.status)}`}>
                            <getStatusIcon(assessment.status) size={12} /> {assessment.status}
                          </span>
                        </td>
                        <td>
                          <span className="badge badge-info">{assessment.engine || 'solve'}</span>
                        </td>
                        <td>
                          <div style={{ width: '100px', height: '6px', background: 'var(--border)', borderRadius: '3px', overflow: 'hidden' }}>
                            <div style={{ width: `${assessment.progress || 0}%`, height: '100%', background: 'var(--accent)', transition: 'width 0.3s' }}></div>
                          </div>
                        </td>
                        <td style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>
                          {formatDistanceToNow(new Date(assessment.created_at), { addSuffix: true })}
                        </td>
                        <td>
                          <Link to={`/assessments/${assessment.assessment_id}`} className="btn btn-secondary" style={{ padding: '0.25rem 0.5rem', fontSize: '0.7rem' }}>
                            <Eye size={12} /> View
                          </Link>
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          )}

        </div>

        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Recent Activity</h3>
          </div>
          {recentActivity.length === 0 ? (
            <div className="empty-state" style={{ padding: '2rem' }}>
              <Activity size={48} />
              <h4>No recent activity</h4>
              <p>Activity will appear here as assessments run</p>
            </div>
          ) : (
            <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
              {recentActivity.map((activity, index) => (
                <div key={index} style={{ display: 'flex', alignItems: 'flex-start', gap: '0.75rem', padding: '0.75rem 0', borderBottom: '1px solid var(--border)' }}>
                  <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: 'var(--accent)', marginTop: '0.35rem', flexShrink: 0 }} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.25rem' }}>
                      <span style={{ fontWeight: 500 }}>{activity.message || activity.description}</span>
                      <span style={{ color: 'var(--text-secondary)', fontSize: '0.75rem' }}>
                        {formatDistanceToNow(new Date(activity.timestamp), { addSuffix: true })}
                      </span>
                    </div>
                    {activity.details && (
                      <div style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', fontFamily: 'monospace' }}>
                        {activity.details}
                      </div>
                    )}
                  </div>
                ))}
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function getStatusBadge(status) {
  const badges = {
    pending: 'info',
    running: 'warning',
    completed: 'success',
    failed: 'error',
    cancelled: 'neutral',
  };
  return badges[status] || 'neutral';
}

function getStatusIcon(status) {
  const icons = {
    pending: Clock,
    running: Zap,
    completed: CheckCircle,
    failed: XCircle,
    cancelled: AlertTriangle,
  };
  return icons[status] || Clock;
}

export default Dashboard;