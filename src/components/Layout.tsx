import React, { useState } from "react";
import { NavLink, useLocation } from "react-router-dom";
import {
  LayoutDashboard,
  Layers,
  Menu,
  Shield,
  ChevronLeft,
  LogOut,
  Users,
  ShieldAlert,
  ShieldCheck,
  Gauge,
  Bug,
  ScanSearch,
  Fingerprint,
  FileText,
  Server,
  Settings,
  Sliders,
  Bot,
  Terminal,
  Eye,
  ClipboardCheck,
  ClipboardList,
  Info,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { useSetup } from "../context/SetupContext";
import { useCurrentUser } from "../context/UserContext";
import StatusBar from "./StatusBar";

interface LayoutProps {
  children: React.ReactNode;
}

function Layout({ children }: LayoutProps) {
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const location = useLocation();
  const { logout } = useAuth();
  const { connected, deployMode } = useSetup();
  const { isAdmin, currentUser } = useCurrentUser();

  type Item = { name: string; href: string; icon: React.ElementType; matchPrefix?: boolean };
  type Section = { label: string; items: Item[] };

  const sections: Section[] = [
    {
      label: "首页",
      items: [
        { name: "安全总览", href: "/", icon: LayoutDashboard },
      ],
    },
    {
      label: "模型防护中心",
      items: [
        ...(isAdmin
          ? [
              { name: "实时防护", href: "/alerts/realtime", icon: ShieldAlert } as Item,
              { name: "会话防护", href: "/alerts/threats", icon: Bug } as Item,
            ]
          : []),
      ],
    },
    ...(isAdmin
      ? [
          {
            label: "AI 智能体防护中心",
            items: [
              { name: "环境安全", href: "/agent-security/environment", icon: Bot },
              { name: "运行时安全", href: "/agent-security/runtime", icon: Terminal },
              { name: "安全广场", href: "/security-tools", icon: ScanSearch },
            ],
          },
        ]
      : []),
    {
      label: "管控中心",
      items: [
        { name: "模型管理", href: "/models-mgmt", icon: Layers, matchPrefix: true },
        ...(isAdmin
          ? [
              { name: "用户管理", href: "/user-management", icon: Users } as Item,
              { name: "密钥管控", href: "/key-control", icon: Fingerprint } as Item,
              { name: "流量控制", href: "/rate-limit", icon: Gauge } as Item,
            ]
          : []),
      ],
    },
    ...(isAdmin
      ? [
          {
            label: "审计中心",
            items: [
              { name: "模型日志", href: "/model-call-logs", icon: FileText },
              { name: "智能体日志", href: "/agent-security/logs", icon: ClipboardCheck },
              { name: "平台操作日志", href: "/audit-logs", icon: ClipboardList },
              { name: "平台运行日志", href: "/system-logs", icon: Server },
            ],
          },
        ]
      : []),
    {
      label: "设置中心",
      items: [
        { name: "基础设置", href: "/basic-settings", icon: Settings },
        ...(isAdmin
          ? [
              { name: "安全设置", href: "/security-settings", icon: ShieldCheck } as Item,
              { name: "系统设置", href: "/system-settings", icon: Sliders } as Item,
            ]
          : []),
        { name: "关于", href: "/about", icon: Info },
      ],
    },
  ];

  const allItems = sections.flatMap((s) => s.items);
  const currentName =
    allItems.find((item) => {
      if (item.href === "/") return location.pathname === "/";
      if (item.matchPrefix) return location.pathname.startsWith(item.href);
      return location.pathname === item.href;
    })?.name || "ClamAI";

  return (
    <div className="flex h-screen bg-background">
      <aside
        className={`${
          sidebarOpen ? "w-56" : "w-14"
        } bg-card border-r border-border transition-all duration-300 flex flex-col shrink-0`}
      >
        <div className="flex items-center justify-between h-14 px-3 border-b border-border">
          {sidebarOpen && (
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-primary flex items-center justify-center">
                <Shield size={16} className="text-primary-foreground" />
              </div>
              <div>
                <span className="text-sm font-bold text-foreground tracking-wide">ClamAI</span>
                <span className="text-[10px] text-muted-foreground ml-1">Security</span>
              </div>
            </div>
          )}
          <button
            onClick={() => setSidebarOpen(!sidebarOpen)}
            className="p-1.5 rounded-md hover:bg-secondary transition-colors text-muted-foreground hover:text-foreground"
          >
            {sidebarOpen ? <ChevronLeft size={16} /> : <Menu size={16} />}
          </button>
        </div>

        <nav className="flex-1 py-2 overflow-y-auto">
          {sections.map((section, si) =>
            section.items.length > 0 ? (
              <div key={si} className="mb-0.5">
                {sidebarOpen && section.label && (
                  <div className="px-4 pt-3 pb-1">
                    <span className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
                      {section.label}
                    </span>
                  </div>
                )}
                {section.items.map((item) => {
                  const isActive = item.href === "/"
                    ? location.pathname === "/"
                    : item.matchPrefix
                      ? location.pathname.startsWith(item.href)
                      : location.pathname === item.href;
                  return (
                    <NavLink
                      key={item.name + item.href}
                      to={item.href}
                      className={`flex items-center gap-3 mx-2 px-2.5 py-2 rounded-lg transition-all duration-150 group ${
                        isActive
                          ? "sidebar-active text-primary"
                          : "text-muted-foreground hover:text-foreground hover:bg-secondary"
                      }`}
                    >
                      <item.icon
                        size={18}
                        className={`shrink-0 ${isActive ? "text-primary" : "text-muted-foreground group-hover:text-foreground"}`}
                      />
                      {sidebarOpen && (
                        <span className={`text-[13px] ${isActive ? "font-semibold" : "font-medium"}`}>
                          {item.name}
                        </span>
                      )}
                      {isActive && sidebarOpen && (
                        <div className="ml-auto w-1.5 h-1.5 rounded-full bg-primary sidebar-glow-dot" />
                      )}
                    </NavLink>
                  );
                })}
              </div>
            ) : null
          )}
        </nav>

        {sidebarOpen && (
          <div className="px-3 pb-3 space-y-2">
            <div className="border-t border-border pt-3">
              {currentUser && (
                <div className="flex items-center gap-2 px-2 py-1.5 rounded-lg bg-secondary mb-2">
                  <div className={`w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold ${isAdmin ? 'bg-red-500/20 text-red-400' : 'bg-primary/20 text-primary'}`}>
                    {(currentUser.displayName || currentUser.username).charAt(0).toUpperCase()}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-xs text-foreground truncate">{currentUser.displayName || currentUser.username}</p>
                    <p className="text-[10px] text-muted-foreground">{isAdmin ? '管理员' : '用户'}</p>
                  </div>
                </div>
              )}
              <button
                onClick={logout}
                className="w-full flex items-center gap-2 px-2 py-1.5 text-xs text-muted-foreground hover:text-foreground hover:bg-secondary rounded-lg transition-colors"
              >
                <LogOut className="w-3.5 h-3.5" />
                退出登录
              </button>
            </div>
          </div>
        )}
      </aside>

      <div className="flex-1 flex flex-col overflow-hidden">
        <header className="h-14 bg-card/80 backdrop-blur-md border-b border-border flex items-center justify-between px-6 shrink-0">
          <h1 className="text-sm font-semibold text-foreground">{currentName}</h1>
          <div className="flex items-center gap-2 text-xs">
            <div
              className={`w-1.5 h-1.5 rounded-full ${
                connected ? "bg-emerald-400 status-dot-safe" : "bg-red-400 status-dot-danger"
              }`}
            />
            <span className={connected ? "text-emerald-400" : "text-red-400"}>
              {connected ? (deployMode === "pc" ? "本地服务正常" : "远程服务正常") : "服务未连接"}
            </span>
          </div>
        </header>
        <main className="flex-1 overflow-y-auto">
          <div className="max-w-[1400px] mx-auto p-6">{children}</div>
        </main>
        <StatusBar />
      </div>
    </div>
  );
}

export default Layout;
