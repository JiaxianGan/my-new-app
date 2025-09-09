import React, { useState, useEffect, useRef } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, PieChart, Pie, Cell } from 'recharts';
import { Shield, AlertTriangle, Users, Activity, Globe, Lock, Eye, Bell, Download, Filter, LogOut, User } from 'lucide-react';
import { collection, addDoc, getDocs, query, where, orderBy, limit, doc, setDoc, getDoc } from 'firebase/firestore';
import { signInWithEmailAndPassword, signOut, onAuthStateChanged } from 'firebase/auth';
import { db, auth } from './firebase';

// Modal Component
const Modal = ({ isOpen, onClose, title, children }) => {
  if (!isOpen) return null;
  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white p-6 rounded-lg max-w-md w-full">
        <div className="flex justify-between items-center mb-4">
          <h3 className="text-lg font-semibold">{title}</h3>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-700 text-xl">
            ×
          </button>
        </div>
        {children}
      </div>
    </div>
  );
};

// Login Component
const LoginPage = ({ onLogin }) => {
  const [credentials, setCredentials] = useState({
    email: '',
    password: ''
  });
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError('');

    try {
      const userCredential = await signInWithEmailAndPassword(auth, credentials.email, credentials.password);
      const user = userCredential.user;
      const userDoc = await getDoc(doc(db, 'users', user.uid));
      if (userDoc.exists()) {
        const userData = userDoc.data();
        onLogin({ uid: user.uid, email: user.email, username: userData.username, role: userData.role });
      } else {
        setError('User metadata not found');
      }
    } catch (err) {
      setError('Invalid email or password');
      console.error('Login error:', err);
    }
    setIsLoading(false);
  };

  const handleInputChange = (e) => {
    setCredentials({
      ...credentials,
      [e.target.name]: e.target.value
    });
    setError('');
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-900 via-blue-800 to-indigo-900 flex items-center justify-center p-4">
      <div className="max-w-md w-full space-y-8">
        <div className="text-center">
          <div className="mx-auto h-12 w-12 flex items-center justify-center rounded-full bg-blue-100">
            <Shield className="h-8 w-8 text-blue-600" />
          </div>
          <h2 className="mt-6 text-3xl font-extrabold text-white">
            CIMB Bank Security
          </h2>
          <p className="mt-2 text-sm text-blue-200">
            Sign in to access the security dashboard
          </p>
        </div>
        <div className="bg-white rounded-lg shadow-xl p-8">
          <form className="space-y-6" onSubmit={handleSubmit}>
            {error && (
              <div className="bg-red-50 border-l-4 border-red-400 p-4 rounded">
                <div className="flex">
                  <AlertTriangle className="h-5 w-5 text-red-400" />
                  <div className="ml-3">
                    <p className="text-sm text-red-700">{error}</p>
                  </div>
                </div>
              </div>
            )}
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700">
                Email
              </label>
              <div className="mt-1 relative">
                <input
                  id="email"
                  name="email"
                  type="email"
                  required
                  className="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  placeholder="Enter your email"
                  value={credentials.email}
                  onChange={handleInputChange}
                />
                <User className="absolute right-3 top-2.5 h-5 w-5 text-gray-400" />
              </div>
            </div>
            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700">
                Password
              </label>
              <div className="mt-1 relative">
                <input
                  id="password"
                  name="password"
                  type="password"
                  required
                  className="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  placeholder="Enter your password"
                  value={credentials.password}
                  onChange={handleInputChange}
                />
                <Lock className="absolute right-3 top-2.5 h-5 w-5 text-gray-400" />
              </div>
            </div>
            <div>
              <button
                type="submit"
                disabled={isLoading}
                className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isLoading ? 'Signing in...' : 'Sign in'}
              </button>
            </div>
          </form>
          <div className="mt-6 border-t border-gray-200 pt-6">
            <p className="text-xs text-gray-500 mb-2">Demo credentials:</p>
            <div className="text-xs text-gray-600 space-y-1">
              <div>👤 <strong>admin@example.com</strong> / admin123 (Administrator)</div>
              <div>👤 <strong>manager@example.com</strong> / manager123 (Manager)</div>
              <div>👤 <strong>security@example.com</strong> / security123 (Security Analyst)</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// Security Dashboard Component
const SecuritySystemDashboard = ({ user, onLogout }) => {
  const [currentTime, setCurrentTime] = useState(new Date());
  const [trafficData, setTrafficData] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [blockedAttempts, setBlockedAttempts] = useState([]);
  const [userBehaviorData, setUserBehaviorData] = useState([]);
  const [dnsFilteringData, setDnsFilteringData] = useState([]);
  const [systemStats, setSystemStats] = useState({
    totalUsers: 1247,
    activeConnections: 89,
    blockedAttempts: 0,
    alertsToday: 0
  });
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [selectedBlockedAttempt, setSelectedBlockedAttempt] = useState(null);
  const [error, setError] = useState('');
  const trafficDataRef = useRef([]);
  const archivedDataRef = useRef([]);

  // Load data from Firestore
  useEffect(() => {
    const loadData = async () => {
      try {
        // Load active traffic data
        const trafficQuery = query(collection(db, 'active_traffic'), orderBy('timestamp', 'desc'), limit(20));
        const trafficSnapshot = await getDocs(trafficQuery);
        const loadedTraffic = trafficSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        setTrafficData(loadedTraffic);
        trafficDataRef.current = loadedTraffic;

        // Load archived traffic data
        const archivedQuery = query(collection(db, 'archived_traffic'));
        const archivedSnapshot = await getDocs(archivedQuery);
        archivedDataRef.current = archivedSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));

        // Load alerts
        const alertsQuery = query(collection(db, 'alerts'), orderBy('timestamp', 'desc'), limit(10));
        const alertsSnapshot = await getDocs(alertsQuery);
        const loadedAlerts = alertsSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        setAlerts(loadedAlerts);

        // Load blocked attempts
        const blockedQuery = query(collection(db, 'blocked_attempts'), orderBy('timestamp', 'desc'), limit(10));
        const blockedSnapshot = await getDocs(blockedQuery);
        const loadedBlocked = blockedSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        setBlockedAttempts(loadedBlocked);

        // Load user behavior
        const userBehaviorSnapshot = await getDocs(collection(db, 'user_behavior'));
        const loadedUserBehavior = userBehaviorSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        setUserBehaviorData(loadedUserBehavior);

        // Load DNS filtering
        const dnsFilteringSnapshot = await getDocs(collection(db, 'dns_filtering'));
        const loadedDnsFiltering = dnsFilteringSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        setDnsFilteringData(loadedDnsFiltering);

        // Load system stats
        const statsSnapshot = await getDocs(collection(db, 'system_stats'));
        if (!statsSnapshot.empty) {
          setSystemStats(statsSnapshot.docs[0].data());
        } else {
          const initialStats = {
            totalUsers: 1247,
            activeConnections: 89,
            blockedAttempts: 0,
            alertsToday: 0
          };
          await setDoc(doc(db, 'system_stats', 'stats'), initialStats);
          setSystemStats(initialStats);
        }

        // Initialize sample data if collections are empty
        if (loadedTraffic.length === 0) {
          const initialTrafficData = Array.from({length: 10}, (_, i) => ({
            time: new Date(Date.now() - (10 - i) * 5000).toLocaleTimeString(),
            timestamp: Date.now() - (10 - i) * 5000,
            inbound: Math.floor(Math.random() * 100) + 20,
            outbound: Math.floor(Math.random() * 80) + 15,
            threats: Math.floor(Math.random() * 5),
            dns_blocked: Math.floor(Math.random() * 3)
          }));
          for (const data of initialTrafficData) {
            await addDoc(collection(db, 'active_traffic'), data);
          }
          setTrafficData(initialTrafficData);
          trafficDataRef.current = initialTrafficData;
        }

        if (loadedUserBehavior.length === 0) {
          const initialUserBehavior = [
            { hour: '00:00', normal: 45, suspicious: 2, anomalous: 1 },
            { hour: '04:00', normal: 23, suspicious: 1, anomalous: 0 },
            { hour: '08:00', normal: 234, suspicious: 12, anomalous: 3 },
            { hour: '12:00', normal: 456, suspicious: 8, anomalous: 2 },
            { hour: '16:00', normal: 378, suspicious: 15, anomalous: 5 },
            { hour: '20:00', normal: 167, suspicious: 6, anomalous: 1 }
          ];
          for (const data of initialUserBehavior) {
            await addDoc(collection(db, 'user_behavior'), data);
          }
          setUserBehaviorData(initialUserBehavior);
        }

        if (loadedDnsFiltering.length === 0) {
          const initialDnsFiltering = [
            { category: 'Malware', blocked: 45, percentage: 35 },
            { category: 'Phishing', blocked: 32, percentage: 25 },
            { category: 'Adult Content', blocked: 28, percentage: 22 },
            { category: 'Social Media', blocked: 15, percentage: 12 },
            { category: 'Gambling', blocked: 8, percentage: 6 }
          ];
          for (const data of initialDnsFiltering) {
            await addDoc(collection(db, 'dns_filtering'), data);
          }
          setDnsFilteringData(initialDnsFiltering);
        }

        if (loadedAlerts.length === 0) {
          const initialAlerts = [
            { type: 'High Risk', message: 'Unusual login pattern detected from IP 203.***.***.***', time: '10:45:23', severity: 'high', timestamp: Date.now() },
            { type: 'DNS Alert', message: 'Multiple malware domain requests blocked', time: '10:42:15', severity: 'medium', timestamp: Date.now() },
            { type: 'Behavior Alert', message: 'User accessing sensitive data outside normal hours', time: '10:38:42', severity: 'medium', timestamp: Date.now() }
          ];
          for (const data of initialAlerts) {
            await addDoc(collection(db, 'alerts'), data);
          }
          setAlerts(initialAlerts);
        }

        if (loadedBlocked.length === 0) {
          const initialBlocked = [
            { username: 'admin***', ip: '192.168.1.***', time: '10:45:23', reason: 'Invalid credentials', timestamp: Date.now() },
            { username: 'user***', ip: '10.0.1.***', time: '10:42:15', reason: 'Multiple failed attempts', timestamp: Date.now() },
            { username: 'test***', ip: '172.16.0.***', time: '10:38:42', reason: 'Suspicious behavior pattern', timestamp: Date.now() }
          ];
          for (const data of initialBlocked) {
            await addDoc(collection(db, 'blocked_attempts'), data);
          }
          setBlockedAttempts(initialBlocked);
        }
      } catch (error) {
        setError('Failed to load data. Please try again.');
        console.error('Error loading data:', error);
      }
    };

    loadData();
  }, []);

  // Save data to Firestore
  const saveToDb = async (collectionName, data) => {
    try {
      await addDoc(collection(db, collectionName), { ...data, timestamp: Date.now() });
    } catch (error) {
      setError(`Failed to save data to ${collectionName}.`);
      console.error(`Error saving to ${collectionName}:`, error);
    }
  };

  // Update system stats in Firestore
  const updateSystemStats = async (stats) => {
    try {
      await setDoc(doc(db, 'system_stats', 'stats'), stats);
    } catch (error) {
      setError('Failed to update system stats.');
      console.error('Error updating system stats:', error);
    }
  };

  // Simulated real-time traffic monitoring
  useEffect(() => {
    const interval = setInterval(async () => {
      const now = new Date();
      setCurrentTime(now);

      const newTrafficPoint = {
        time: now.toLocaleTimeString(),
        timestamp: now.getTime(),
        inbound: Math.floor(Math.random() * 100) + 20,
        outbound: Math.floor(Math.random() * 80) + 15,
        threats: Math.floor(Math.random() * 5),
        dns_blocked: Math.floor(Math.random() * 3)
      };

      await saveToDb('active_traffic', newTrafficPoint);
      setTrafficData(prev => {
        const updated = [...prev, newTrafficPoint].slice(-20);
        trafficDataRef.current = updated;
        return updated;
      });

      await archiveOldData();

      if (Math.random() < 0.1) {
        await generateSecurityAlert();
      }
      if (Math.random() < 0.15) {
        await generateBlockedAttempt();
      }
    }, 5000);

    return () => clearInterval(interval);
  }, []);

  const archiveOldData = async () => {
    try {
      const threeDaysAgo = Date.now() - (3 * 24 * 60 * 60 * 1000);
      const trafficQuery = query(collection(db, 'active_traffic'), where('timestamp', '<', threeDaysAgo));
      const trafficSnapshot = await getDocs(trafficQuery);

      const batch = [];
      trafficSnapshot.docs.forEach(doc => {
        batch.push(addDoc(collection(db, 'archived_traffic'), doc.data()));
        batch.push(doc.ref.delete());
      });
      await Promise.all(batch);

      const updatedTraffic = trafficDataRef.current.filter(item => item.timestamp >= threeDaysAgo);
      setTrafficData(updatedTraffic);
      trafficDataRef.current = updatedTraffic;

      const archivedSnapshot = await getDocs(collection(db, 'archived_traffic'));
      archivedDataRef.current = archivedSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    } catch (error) {
      setError('Failed to archive data.');
      console.error('Error archiving data:', error);
    }
  };

  const generateSecurityAlert = async () => {
    const alertTypes = ['High Risk', 'Medium Risk', 'DNS Alert', 'Behavior Alert', 'System Alert'];
    const messages = [
      'Potential brute force attack detected',
      'Unusual data access pattern identified',
      'Malicious domain access blocked',
      'Suspicious file download detected',
      'Multiple failed login attempts from single IP'
    ];

    const newAlert = {
      type: alertTypes[Math.floor(Math.random() * alertTypes.length)],
      message: messages[Math.floor(Math.random() * messages.length)],
      time: new Date().toLocaleTimeString(),
      severity: Math.random() > 0.3 ? 'medium' : 'high'
    };

    await saveToDb('alerts', newAlert);
    setAlerts(prev => {
      const updated = [newAlert, ...prev].slice(0, 10);
      return updated;
    });
    setSystemStats(prev => {
      const updated = { ...prev, alertsToday: prev.alertsToday + 1 };
      updateSystemStats(updated);
      return updated;
    });
  };

  const generateBlockedAttempt = async () => {
    const usernames = ['admin***', 'user***', 'test***', 'guest***', 'system***'];
    const ips = ['192.168.1.***', '10.0.1.***', '172.16.0.***', '203.***.***.***'];
    const reasons = ['Invalid credentials', 'Multiple failed attempts', 'Suspicious behavior pattern', 'Account locked'];

    const newAttempt = {
      username: usernames[Math.floor(Math.random() * usernames.length)],
      ip: ips[Math.floor(Math.random() * ips.length)],
      time: new Date().toLocaleTimeString(),
      reason: reasons[Math.floor(Math.random() * reasons.length)]
    };

    await saveToDb('blocked_attempts', newAttempt);
    setBlockedAttempts(prev => {
      const updated = [newAttempt, ...prev].slice(0, 10);
      return updated;
    });
    setSystemStats(prev => {
      const updated = { ...prev, blockedAttempts: prev.blockedAttempts + 1 };
      updateSystemStats(updated);
      return updated;
    });
  };

  const COLORS = ['#ef4444', '#f97316', '#eab308', '#22c55e', '#3b82f6'];

  const hasAccess = (allowedRoles) => allowedRoles.includes(user.role);

  const canViewStatistics = hasAccess(['Administrator', 'Manager', 'Security Analyst']);
  const canViewTrafficMonitor = hasAccess(['Administrator', 'Manager', 'Security Analyst']);
  const canViewUserBehavior = hasAccess(['Administrator', 'Manager']);
  const canViewDnsFiltering = hasAccess(['Administrator', 'Manager']);
  const canViewSecurityAlerts = hasAccess(['Administrator', 'Security Analyst']);
  const canViewBlockedAttempts = hasAccess(['Administrator', 'Security Analyst']);
  const canViewDataManagement = hasAccess(['Administrator']);

  return (
    <div className="min-h-screen bg-gray-100 p-6">
      {error && (
        <div className="bg-red-50 border-l-4 border-red-400 p-4 rounded mb-6">
          <p className="text-sm text-red-700">{error}</p>
        </div>
      )}
      <div className="bg-white rounded-lg shadow-sm p-6 mb-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <Shield className="w-8 h-8 text-blue-600" />
            <div>
              <h1 className="text-2xl font-bold text-gray-800">CIMB Bank Security System</h1>
              <p className="text-gray-600">Real-time Security Monitoring & Analysis</p>
            </div>
          </div>
          <div className="flex items-center space-x-4">
            <div className="text-right">
              <div className="text-sm text-gray-500">Last Updated</div>
              <div className="text-lg font-semibold text-gray-800">{currentTime.toLocaleTimeString()}</div>
            </div>
            <div className="border-l border-gray-200 pl-4">
              <div className="flex items-center space-x-3">
                <div className="text-right">
                  <div className="text-sm font-semibold text-gray-800">{user.username}</div>
                  <div className="text-xs text-gray-500">{user.role}</div>
                </div>
                <button
                  onClick={onLogout}
                  className="flex items-center space-x-1 px-3 py-2 text-sm text-red-600 hover:bg-red-50 rounded-md transition-colors"
                  title="Logout"
                >
                  <LogOut className="w-4 h-4" />
                  <span>Logout</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      {canViewStatistics && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-6">
          <div className="bg-white rounded-lg shadow-sm p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Total Users</p>
                <p className="text-3xl font-bold text-gray-800">{systemStats.totalUsers}</p>
              </div>
              <Users className="w-8 h-8 text-blue-500" />
            </div>
          </div>
          <div className="bg-white rounded-lg shadow-sm p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Active Connections</p>
                <p className="text-3xl font-bold text-green-600">{systemStats.activeConnections}</p>
              </div>
              <Activity className="w-8 h-8 text-green-500" />
            </div>
          </div>
          <div className="bg-white rounded-lg shadow-sm p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Blocked Attempts</p>
                <p className="text-3xl font-bold text-red-600">{systemStats.blockedAttempts}</p>
              </div>
              <Lock className="w-8 h-8 text-red-500" />
            </div>
          </div>
          <div className="bg-white rounded-lg shadow-sm p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Alerts Today</p>
                <p className="text-3xl font-bold text-orange-600">{systemStats.alertsToday}</p>
              </div>
              <Bell className="w-8 h-8 text-orange-500" />
            </div>
          </div>
        </div>
      )}

      {canViewTrafficMonitor && (
        <div className="bg-white rounded-lg shadow-sm p-6 mb-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-xl font-semibold text-gray-800 flex items-center">
              <Globe className="w-5 h-5 mr-2" />
              Real-time Internet Traffic Monitor (5s polling)
            </h2>
            <div className="text-sm text-gray-500">
              Data refreshes every 5 seconds
            </div>
          </div>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={trafficData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="time" />
              <YAxis />
              <Tooltip />
              <Line type="monotone" dataKey="inbound" stroke="#3b82f6" name="Inbound Traffic" strokeWidth={2} />
              <Line type="monotone" dataKey="outbound" stroke="#10b981" name="Outbound Traffic" strokeWidth={2} />
              <Line type="monotone" dataKey="threats" stroke="#ef4444" name="Threats Detected" strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}

      {(canViewUserBehavior || canViewDnsFiltering) && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
          {canViewUserBehavior && (
            <div className="bg-white rounded-lg shadow-sm p-6">
              <h2 className="text-xl font-semibold text-gray-800 mb-4 flex items-center">
                <Eye className="w-5 h-5 mr-2" />
                User Behavior Analysis
              </h2>
              <ResponsiveContainer width="100%" height={250}>
                <BarChart data={userBehaviorData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="hour" />
                  <YAxis />
                  <Tooltip />
                  <Bar dataKey="normal" fill="#22c55e" name="Normal" />
                  <Bar dataKey="suspicious" fill="#eab308" name="Suspicious" />
                  <Bar dataKey="anomalous" fill="#ef4444" name="Anomalous" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
          {canViewDnsFiltering && (
            <div className="bg-white rounded-lg shadow-sm p-6">
              <h2 className="text-xl font-semibold text-gray-800 mb-4 flex items-center">
                <Filter className="w-5 h-5 mr-2" />
                DNS Filtering Statistics
              </h2>
              <ResponsiveContainer width="100%" height={250}>
                <PieChart>
                  <Pie
                    data={dnsFilteringData}
                    cx="50%"
                    cy="50%"
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="blocked"
                    label={({category, percentage}) => `${category}: ${percentage}%`}
                  >
                    {dnsFilteringData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      )}

      {(canViewSecurityAlerts || canViewBlockedAttempts) && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {canViewSecurityAlerts && (
            <div className="bg-white rounded-lg shadow-sm p-6">
              <h2 className="text-xl font-semibold text-gray-800 mb-4 flex items-center">
                <AlertTriangle className="w-5 h-5 mr-2" />
                Security Alerts
              </h2>
              <div className="space-y-3 max-h-64 overflow-y-auto">
                {alerts.map(alert => (
                  <div key={alert.id} className={`border-l-4 p-3 ${alert.severity === 'high' ? 'border-red-500 bg-red-50' : 'border-yellow-500 bg-yellow-50'}`}>
                    <div className="flex items-center justify-between mb-2">
                      <span className={`text-xs font-semibold px-2 py-1 rounded ${alert.severity === 'high' ? 'bg-red-100 text-red-800' : 'bg-yellow-100 text-yellow-800'}`}>
                        {alert.type}
                      </span>
                      <span className="text-xs text-gray-500">{alert.time}</span>
                    </div>
                    <p className="text-sm text-gray-700 mb-2">{alert.message}</p>
                    <button
                      onClick={() => setSelectedAlert(alert)}
                      className="text-blue-600 text-xs hover:underline"
                    >
                      View Details
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}
          {canViewBlockedAttempts && (
            <div className="bg-white rounded-lg shadow-sm p-6">
              <h2 className="text-xl font-semibold text-gray-800 mb-4 flex items-center">
                <Lock className="w-5 h-5 mr-2" />
                Blocked Login Attempts
              </h2>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b">
                      <th className="text-left py-2">Username</th>
                      <th className="text-left py-2">IP Address</th>
                      <th className="text-left py-2">Time</th>
                      <th className="text-left py-2">Reason</th>
                      <th className="text-left py-2">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {blockedAttempts.map(attempt => (
                      <tr key={attempt.id} className="border-b border-gray-100">
                        <td className="py-2 font-mono">{attempt.username}</td>
                        <td className="py-2 font-mono">{attempt.ip}</td>
                        <td className="py-2">{attempt.time}</td>
                        <td className="py-2">
                          <span className="bg-red-100 text-red-800 text-xs px-2 py-1 rounded">
                            {attempt.reason}
                          </span>
                        </td>
                        <td className="py-2">
                          <button
                            onClick={() => setSelectedBlockedAttempt(attempt)}
                            className="text-blue-600 hover:underline text-sm"
                          >
                            View Details
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {canViewDataManagement && (
        <div className="mt-6 bg-blue-50 border-l-4 border-blue-500 p-4 rounded">
          <div className="flex items-center">
            <Download className="w-5 h-5 text-blue-500 mr-2" />
            <div>
              <h3 className="text-sm font-semibold text-blue-800">Data Storage Management</h3>
              <p className="text-sm text-blue-700 mt-1">
                Real-time data is stored in Firestore active database. Data older than 3 days is automatically archived. 
                Current active data points: {trafficData.length} | Archived data points: {archivedDataRef.current.length}
              </p>
            </div>
          </div>
        </div>
      )}

      <Modal
        isOpen={!!selectedAlert}
        onClose={() => setSelectedAlert(null)}
        title="Security Alert Details"
      >
        {selectedAlert && (
          <div className="space-y-2">
            <p><strong>Type:</strong> {selectedAlert.type}</p>
            <p><strong>Severity:</strong> {selectedAlert.severity.toUpperCase()}</p>
            <p><strong>When:</strong> {selectedAlert.time}</p>
            <p><strong>What Happened:</strong> {selectedAlert.message}</p>
          </div>
        )}
      </Modal>

      <Modal
        isOpen={!!selectedBlockedAttempt}
        onClose={() => setSelectedBlockedAttempt(null)}
        title="Blocked Login Attempt Details"
      >
        {selectedBlockedAttempt && (
          <div className="space-y-2">
            <p><strong>Username:</strong> {selectedBlockedAttempt.username}</p>
            <p><strong>Where (IP):</strong> {selectedBlockedAttempt.ip}</p>
            <p><strong>When:</strong> {selectedBlockedAttempt.time}</p>
            <p><strong>What Happened (Reason):</strong> {selectedBlockedAttempt.reason}</p>
          </div>
        )}
      </Modal>
    </div>
  );
};

// Main App Component
const App = () => {
  const [user, setUser] = useState(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, async (firebaseUser) => {
      if (firebaseUser) {
        const userDoc = await getDoc(doc(db, 'users', firebaseUser.uid));
        if (userDoc.exists()) {
          const userData = userDoc.data();
          setUser({ uid: firebaseUser.uid, email: firebaseUser.email, username: userData.username, role: userData.role });
          setIsAuthenticated(true);
        } else {
          console.error('User metadata not found');
          setIsAuthenticated(false);
        }
      } else {
        setUser(null);
        setIsAuthenticated(false);
      }
    });

    return () => unsubscribe();
  }, []);

  const handleLogin = (userData) => {
    setUser(userData);
    setIsAuthenticated(true);
  };

  const handleLogout = async () => {
    try {
      await signOut(auth);
      setUser(null);
      setIsAuthenticated(false);
    } catch (error) {
      console.error('Logout error:', error);
    }
  };

  if (!isAuthenticated) {
    return <LoginPage onLogin={handleLogin} />;
  }

  return <SecuritySystemDashboard user={user} onLogout={handleLogout} />;
};

export default App;