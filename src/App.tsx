import { Routes, Route, Navigate } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import React, { Component, type ReactNode, Suspense, useCallback, useEffect } from "react";

import Layout from "./components/Layout";
import ConnectBanner from "./components/ConnectBanner";
import { ApiKeySecretsProvider } from "./context/ApiKeySecretsContext";
import { AuthProvider, useAuth } from "./context/AuthContext";
import { UserProvider, useCurrentUser } from "./context/UserContext";
import { AppProvider } from "./context/AppContext";
import { SetupProvider, useSetup } from "./context/SetupContext";
import { ThemeProvider } from "./context/ThemeContext";

import Login from "./pages/Login";
import SetupWizard from "./pages/SetupWizard";

const Dashboard = React.lazy(() => import("./pages/Dashboard"));
const BasicSettings = React.lazy(() => import("./pages/BasicSettings"));
const ModelManagement = React.lazy(() => import("./pages/ModelManagement"));
const AlertRealtime = React.lazy(() => import("./pages/alerts/Realtime"));
const AlertThreats = React.lazy(() => import("./pages/alerts/Threats"));
const SecurityTools = React.lazy(() => import("./pages/SecurityTools"));
const SecuritySettings = React.lazy(() => import("./pages/SecuritySettings"));
const SystemSettings = React.lazy(() => import("./pages/SystemSettings"));
const UserManagement = React.lazy(() => import("./pages/UserManagement"));
const KeyControl = React.lazy(() => import("./pages/KeyControl"));
const RateLimit = React.lazy(() => import("./pages/RateLimit"));
const ModelCallLogs = React.lazy(() => import("./pages/ModelCallLogs"));
const SystemLogs = React.lazy(() => import("./pages/SystemLogs"));
const AgentEnvironment = React.lazy(() => import("./pages/agent/AgentEnvironment"));
const AgentRuntimeSecurity = React.lazy(() => import("./pages/agent/AgentRuntimeSecurity"));
const AgentLogAudit = React.lazy(() => import("./pages/agent/AgentLogAudit"));
const AuditLogs = React.lazy(() => import("./pages/AuditLogs"));
const About = React.lazy(() => import("./pages/About"));

function LazyPage({ children }: { children: ReactNode }) {
  return <Suspense fallback={<div className="min-h-screen bg-background flex items-center justify-center"><div className="text-muted-foreground">Loading...</div></div>}>{children}</Suspense>;
}

function NotFound() {
  return (
    <div className="min-h-screen bg-background flex items-center justify-center">
      <div className="text-center">
        <h1 className="text-6xl font-bold text-muted-foreground mb-4">404</h1>
        <p className="text-muted-foreground mb-6">页面不存在</p>
        <button onClick={() => window.location.href = "/"} className="px-4 py-2 bg-primary text-primary-foreground rounded-lg">返回首页</button>
      </div>
    </div>
  );
}

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { staleTime: 1000 * 60 * 5, gcTime: 1000 * 60 * 30, retry: 1 },
  },
});

function AdminRoute({ children }: { children: ReactNode }) {
  const { isAdmin } = useCurrentUser();
  if (!isAdmin) return <Navigate to="/" replace />;
  return <>{children}</>;
}

const mainRoutes = (
  <Routes>
    <Route path="/" element={<LazyPage><Dashboard /></LazyPage>} />
    <Route path="/models-mgmt" element={<LazyPage><ModelManagement /></LazyPage>} />
    <Route path="/alerts/realtime" element={<LazyPage><AdminRoute><AlertRealtime /></AdminRoute></LazyPage>} />
    <Route path="/alerts/threats" element={<LazyPage><AdminRoute><AlertThreats /></AdminRoute></LazyPage>} />
    <Route path="/security-tools" element={<LazyPage><SecurityTools /></LazyPage>} />
    <Route path="/user-management" element={<LazyPage><AdminRoute><UserManagement /></AdminRoute></LazyPage>} />
    <Route path="/key-control" element={<LazyPage><AdminRoute><KeyControl /></AdminRoute></LazyPage>} />
    <Route path="/rate-limit" element={<LazyPage><AdminRoute><RateLimit /></AdminRoute></LazyPage>} />
    <Route path="/model-call-logs" element={<LazyPage><AdminRoute><ModelCallLogs /></AdminRoute></LazyPage>} />
    <Route path="/system-logs" element={<LazyPage><AdminRoute><SystemLogs /></AdminRoute></LazyPage>} />
    <Route path="/agent-security/environment" element={<LazyPage><AdminRoute><AgentEnvironment /></AdminRoute></LazyPage>} />
    <Route path="/agent-security/runtime" element={<LazyPage><AdminRoute><AgentRuntimeSecurity /></AdminRoute></LazyPage>} />
    <Route path="/agent-security/logs" element={<LazyPage><AdminRoute><AgentLogAudit /></AdminRoute></LazyPage>} />
    <Route path="/audit-logs" element={<LazyPage><AdminRoute><AuditLogs /></AdminRoute></LazyPage>} />
    <Route path="/basic-settings" element={<LazyPage><BasicSettings /></LazyPage>} />
    <Route path="/security-settings" element={<LazyPage><AdminRoute><SecuritySettings /></AdminRoute></LazyPage>} />
    <Route path="/system-settings" element={<LazyPage><AdminRoute><SystemSettings /></AdminRoute></LazyPage>} />
    <Route path="/about" element={<LazyPage><About /></LazyPage>} />
    <Route path="/providers" element={<Navigate to="/models-mgmt" replace />} />
    <Route path="/models" element={<Navigate to="/models-mgmt" replace />} />
    <Route path="/api-keys" element={<Navigate to="/models-mgmt" replace />} />
    <Route path="/security" element={<Navigate to="/security-settings" replace />} />
    <Route path="/security-alerts" element={<Navigate to="/alerts/realtime" replace />} />
    <Route path="/security-square" element={<Navigate to="/security-tools" replace />} />
    <Route path="/logs" element={<Navigate to="/model-call-logs" replace />} />
    <Route path="/access-control" element={<Navigate to="/model-call-logs" replace />} />
    <Route path="/settings" element={<Navigate to="/basic-settings" replace />} />
    <Route path="/security-policy" element={<Navigate to="/security-settings" replace />} />
    <Route path="/users" element={<Navigate to="/user-management" replace />} />
    <Route path="*" element={<NotFound />} />
  </Routes>
);

class ErrorBoundary extends Component<
  { children: ReactNode },
  { hasError: boolean; error: Error | null }
> {
  constructor(props: { children: ReactNode }) {
    super(props);
    this.state = { hasError: false, error: null };
  }
  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }
  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-background flex items-center justify-center p-8">
          <div className="max-w-md text-center">
            <h1 className="text-2xl font-bold text-destructive mb-4">Something went wrong</h1>
            <p className="text-muted-foreground mb-4 text-sm font-mono break-all">{this.state.error?.message}</p>
            <button onClick={() => { this.setState({ hasError: false, error: null }); window.location.reload(); }} className="px-4 py-2 bg-primary text-primary-foreground rounded-lg">Reload</button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

function AuthExpiredGuard({ children }: { children: ReactNode }) {
  const { handleAuthExpired } = useAuth();
  const interceptor = useCallback((error: unknown) => {
    const msg = error instanceof Error ? error.message : String(error);
    if (msg.includes("AUTH_EXPIRED")) handleAuthExpired();
  }, [handleAuthExpired]);
  useEffect(() => {
    const unsub = queryClient.getQueryCache().subscribe(() => {});
    queryClient.getQueryCache().config.onError = interceptor;
    queryClient.getMutationCache().config.onError = interceptor;
    return unsub;
  }, [interceptor]);
  return <>{children}</>;
}

function AppContent() {
  const { isAuthenticated, isInitialized, initialized, refreshAuth } = useAuth();
  const { setupComplete, setupChecked, connected, checkSetup, deployMode } = useSetup();
  const handleSetupComplete = async () => { await checkSetup(); await refreshAuth(); };
  if (!isInitialized || !setupChecked) return <div className="min-h-screen bg-background flex items-center justify-center"><div className="text-muted-foreground">Loading...</div></div>;
  if (!setupComplete && deployMode !== "server" && !connected) return <SetupWizard onComplete={handleSetupComplete} />;
  if (connected && (!initialized || !isAuthenticated)) return <Login />;
  if (!connected && !isAuthenticated) return <div className="min-h-screen bg-background text-foreground flex items-center justify-center"><div className="text-center"><p className="text-muted-foreground mb-4">服务未连接</p><button onClick={() => window.location.reload()} className="px-4 py-2 bg-primary text-primary-foreground rounded-lg">重新加载</button></div></div>;
  if (isAuthenticated) return <ApiKeySecretsProvider><div className="min-h-screen bg-background text-foreground">{!connected && <ConnectBanner />}<Layout>{mainRoutes}</Layout></div></ApiKeySecretsProvider>;
  return <Login />;
}

function App() {
  return <ErrorBoundary><QueryClientProvider client={queryClient}><ThemeProvider><AuthProvider><UserProvider><AppProvider><SetupProvider><AuthExpiredGuard><AppContent /></AuthExpiredGuard></SetupProvider></AppProvider></UserProvider></AuthProvider></ThemeProvider></QueryClientProvider></ErrorBoundary>;
}

export default App;
