import { useState, useEffect } from "react";
import { apiRequest } from "../api/client";
import {
  Shield,
  ShieldAlert,
  ShieldOff,
  Clock,
  MapPin,
  FileWarning,
  Plus,
  Trash2,
  RefreshCw,
  Save,
  Loader2,
  Ban,
  CheckCircle,
  AlertTriangle,
} from "lucide-react";

interface IPAccessConfig {
  whitelist: string[];
  blacklist: string[];
  grey_duration_minutes: number;
  honeypot_paths: string[];
  enabled: boolean;
}

interface LoginGuardConfig {
  max_attempts: number;
  window_minutes: number;
  block_minutes: number;
}

interface AccessConfig {
  ip_access: IPAccessConfig;
  login_guard: LoginGuardConfig;
}

interface GreyItem {
  ip: string;
  expiry: string;
  source: string;
  expired: boolean;
}

interface SystemSettingsProps {}

export default function SystemSettings(_: SystemSettingsProps) {
  const [config, setConfig] = useState<AccessConfig | null>(null);
  const [greyList, setGreyList] = useState<GreyItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [newWhitelistIP, setNewWhitelistIP] = useState("");
  const [newBlacklistIP, setNewBlacklistIP] = useState("");
  const [newHoneypotPath, setNewHoneypotPath] = useState("");
  const [msg, setMsg] = useState<{ type: "ok" | "err"; text: string } | null>(null);

  const fetchConfig = async () => {
    setLoading(true);
    try {
      const res = await apiRequest<{ config: AccessConfig; grey_active: GreyItem[] }>(
        "GET", "/system/access"
      );
      const cfg = res.config;
      if (!cfg.ip_access) (cfg as any).ip_access = { whitelist: [], blacklist: [], grey_duration_minutes: 30, honeypot_paths: [], enabled: false };
      if (!cfg.login_guard) (cfg as any).login_guard = { max_attempts: 5, window_minutes: 15, block_minutes: 30 };
      if (!cfg.ip_access.whitelist) cfg.ip_access.whitelist = [];
      if (!cfg.ip_access.blacklist) cfg.ip_access.blacklist = [];
      if (!cfg.ip_access.honeypot_paths) cfg.ip_access.honeypot_paths = [];
      setConfig(cfg);
      setGreyList(res.grey_active || []);
    } catch {
      setMsg({ type: "err", text: "加载配置失败" });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchConfig(); }, []);

  const save = async () => {
    if (!config) return;
    setSaving(true);
    setMsg(null);
    try {
      await apiRequest("PUT", "/system/access", config);
      setMsg({ type: "ok", text: "保存成功" });
      setTimeout(() => setMsg(null), 3000);
      fetchConfig();
    } catch {
      setMsg({ type: "err", text: "保存失败" });
    } finally {
      setSaving(false);
    }
  };

  const removeGrey = async (ip: string) => {
    try {
      await apiRequest("DELETE", `/system/access/grey?ip=${encodeURIComponent(ip)}`);
      fetchConfig();
    } catch {}
  };

  const addToList = (field: "whitelist" | "blacklist", value: string) => {
    if (!value.trim() || !config) return;
    const updated = { ...config };
    updated.ip_access = { ...updated.ip_access };
    (updated.ip_access as any)[field] = [...(updated.ip_access as any)[field], value.trim()];
    setConfig(updated);
  };

  const removeFromList = (field: "whitelist" | "blacklist", idx: number) => {
    if (!config) return;
    const updated = { ...config };
    updated.ip_access = { ...updated.ip_access };
    const arr = [...(updated.ip_access as any)[field]];
    arr.splice(idx, 1);
    (updated.ip_access as any)[field] = arr;
    setConfig(updated);
  };

  if (loading) return <div className="flex items-center justify-center py-20"><Loader2 className="w-6 h-6 animate-spin text-primary" /></div>;
  if (!config) return <div className="text-destructive">加载失败</div>;

  const activeGrey = greyList.filter(g => !g.expired);
  const expiredGrey = greyList.filter(g => g.expired);

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Shield className="w-6 h-6 text-primary" />
        <h2 className="text-xl font-bold">系统设置</h2>
        <div className="ml-auto flex items-center gap-2">
          {msg && (
            <span className={`text-xs flex items-center gap-1 ${msg.type === "ok" ? "text-green-500" : "text-red-500"}`}>
              {msg.type === "ok" ? <CheckCircle className="w-3 h-3" /> : <AlertTriangle className="w-3 h-3" />}
              {msg.text}
            </span>
          )}
          <button onClick={fetchConfig} className="p-1.5 text-muted-foreground hover:text-foreground"><RefreshCw className="w-4 h-4" /></button>
          <button onClick={save} disabled={saving} className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 disabled:opacity-50">
            {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
            保存
          </button>
        </div>
      </div>

      {/* IP 访问控制总开关 */}
      <div className="bg-card rounded-lg border border-border p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            {config.ip_access.enabled ? <ShieldAlert className="w-5 h-5 text-green-500" /> : <ShieldOff className="w-5 h-5 text-muted-foreground" />}
            <div>
              <h4 className="text-sm font-medium">IP 访问控制</h4>
              <p className="text-xs text-muted-foreground">启用后将按白名单 → 灰名单 → 黑名单顺序检查 IP（localhost 始终放行）</p>
            </div>
          </div>
          <button onClick={() => { const c = { ...config }; c.ip_access = { ...c.ip_access, enabled: !c.ip_access.enabled }; setConfig(c); }}>
            {config.ip_access.enabled ? <ShieldAlert className="w-8 h-8 text-green-500" /> : <ShieldOff className="w-8 h-8 text-muted-foreground" />}
          </button>
        </div>
      </div>

      {/* 白名单 */}
      <div className="bg-card rounded-lg border border-border p-4 space-y-3">
        <div className="flex items-center gap-2">
          <CheckCircle className="w-4 h-4 text-green-500" />
          <h4 className="text-sm font-medium">IP 白名单</h4>
          <span className="text-xs text-muted-foreground">（白名单内 IP 始终放行，支持 CIDR 如 192.168.1.0/24）</span>
        </div>
        <div className="flex flex-wrap gap-2">
          {config.ip_access.whitelist.map((ip, i) => (
            <span key={i} className="flex items-center gap-1 px-2 py-1 bg-green-500/10 border border-green-500/20 rounded text-xs">
              {ip}
              <button onClick={() => removeFromList("whitelist", i)} className="text-muted-foreground hover:text-red-500"><Trash2 className="w-3 h-3" /></button>
            </span>
          ))}
        </div>
        <div className="flex gap-2">
          <input value={newWhitelistIP} onChange={e => setNewWhitelistIP(e.target.value)} placeholder="如 10.0.0.1 或 10.0.0.0/24" className="flex-1 px-3 py-1.5 bg-background border border-border rounded text-sm" onKeyDown={e => { if (e.key === "Enter") { addToList("whitelist", newWhitelistIP); setNewWhitelistIP(""); } }} />
          <button onClick={() => { addToList("whitelist", newWhitelistIP); setNewWhitelistIP(""); }} className="flex items-center gap-1 px-2 py-1 text-sm border border-border rounded hover:bg-secondary"><Plus className="w-3 h-3" /></button>
        </div>
      </div>

      {/* 黑名单 */}
      <div className="bg-card rounded-lg border border-border p-4 space-y-3">
        <div className="flex items-center gap-2">
          <Ban className="w-4 h-4 text-red-500" />
          <h4 className="text-sm font-medium">IP 黑名单</h4>
          <span className="text-xs text-muted-foreground">（永久封禁，支持 CIDR）</span>
        </div>
        <div className="flex flex-wrap gap-2">
          {config.ip_access.blacklist.map((ip, i) => (
            <span key={i} className="flex items-center gap-1 px-2 py-1 bg-red-500/10 border border-red-500/20 rounded text-xs">
              {ip}
              <button onClick={() => removeFromList("blacklist", i)} className="text-muted-foreground hover:text-red-500"><Trash2 className="w-3 h-3" /></button>
            </span>
          ))}
        </div>
        <div className="flex gap-2">
          <input value={newBlacklistIP} onChange={e => setNewBlacklistIP(e.target.value)} placeholder="如 1.2.3.4 或 1.2.3.0/24" className="flex-1 px-3 py-1.5 bg-background border border-border rounded text-sm" onKeyDown={e => { if (e.key === "Enter") { addToList("blacklist", newBlacklistIP); setNewBlacklistIP(""); } }} />
          <button onClick={() => { addToList("blacklist", newBlacklistIP); setNewBlacklistIP(""); }} className="flex items-center gap-1 px-2 py-1 text-sm border border-border rounded hover:bg-secondary"><Plus className="w-3 h-3" /></button>
        </div>
      </div>

      {/* 灰名单时长 + 当前灰名单 */}
      <div className="bg-card rounded-lg border border-border p-4 space-y-3">
        <div className="flex items-center gap-2">
          <Clock className="w-4 h-4 text-yellow-500" />
          <h4 className="text-sm font-medium">灰名单</h4>
        </div>
        <div className="flex items-center gap-3">
          <label className="text-xs text-muted-foreground">灰名单自动解除时长</label>
          <input type="number" min={1} value={config.ip_access.grey_duration_minutes} onChange={e => { const c = { ...config }; c.ip_access = { ...c.ip_access, grey_duration_minutes: parseInt(e.target.value) || 30 }; setConfig(c); }} className="w-20 px-2 py-1 bg-background border border-border rounded text-sm text-center" />
          <span className="text-xs text-muted-foreground">分钟</span>
        </div>
        {greyList.length > 0 ? (
          <div className="space-y-3">
            {activeGrey.length > 0 && (
              <div className="space-y-1">
                <p className="text-xs text-muted-foreground">活跃灰名单（{activeGrey.length} 条）</p>
                {activeGrey.map(g => (
                  <div key={g.ip} className="flex items-center justify-between px-2 py-1 bg-yellow-500/5 border border-yellow-500/20 rounded text-xs">
                    <span className="flex items-center gap-2">
                      <MapPin className="w-3 h-3" />{g.ip}
                      <span className={`px-1.5 py-0.5 rounded text-[10px] ${g.source === "honeypot" ? "bg-orange-500/10 text-orange-500" : "bg-red-500/10 text-red-500"}`}>
                        {g.source === "honeypot" ? "蜜罐" : "登录爆破"}
                      </span>
                    </span>
                    <span className="flex items-center gap-2">
                      <span className="text-muted-foreground">到期 {new Date(g.expiry).toLocaleTimeString()}</span>
                      <button onClick={() => removeGrey(g.ip)} className="text-muted-foreground hover:text-green-500" title="手动解除">解除</button>
                    </span>
                  </div>
                ))}
              </div>
            )}
            {expiredGrey.length > 0 && (
              <div className="space-y-1">
                <p className="text-xs text-muted-foreground">已过期待清理（{expiredGrey.length} 条）</p>
                {expiredGrey.map(g => (
                  <div key={g.ip} className="flex items-center justify-between px-2 py-1 bg-muted/50 border border-border rounded text-xs opacity-50">
                    <span className="flex items-center gap-2">
                      <MapPin className="w-3 h-3" />{g.ip}
                      <span className={`px-1.5 py-0.5 rounded text-[10px] ${g.source === "honeypot" ? "bg-orange-500/10 text-orange-500" : "bg-red-500/10 text-red-500"}`}>
                        {g.source === "honeypot" ? "蜜罐" : "登录爆破"}
                      </span>
                    </span>
                    <span className="flex items-center gap-2">
                      <span className="text-muted-foreground">已于 {new Date(g.expiry).toLocaleTimeString()} 过期</span>
                      <button onClick={() => removeGrey(g.ip)} className="text-muted-foreground hover:text-red-500" title="立即清除">清除</button>
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        ) : (
          <p className="text-xs text-muted-foreground py-2 text-center">灰名单为空</p>
        )}
      </div>

      {/* 蜜罐路径 */}
      <div className="bg-card rounded-lg border border-border p-4 space-y-3">
        <div className="flex items-center gap-2">
          <FileWarning className="w-4 h-4 text-orange-500" />
          <h4 className="text-sm font-medium">蜜罐路径</h4>
          <span className="text-xs text-muted-foreground">（访问这些路径的 IP 立即加入灰名单）</span>
        </div>
        <div className="flex flex-wrap gap-2">
          {config.ip_access.honeypot_paths.map((p, i) => (
            <span key={i} className="flex items-center gap-1 px-2 py-1 bg-orange-500/10 border border-orange-500/20 rounded text-xs font-mono">
              {p}
              <button onClick={() => { const c = { ...config }; c.ip_access = { ...c.ip_access }; const arr = [...c.ip_access.honeypot_paths]; arr.splice(i, 1); c.ip_access.honeypot_paths = arr; setConfig(c); }} className="text-muted-foreground hover:text-red-500"><Trash2 className="w-3 h-3" /></button>
            </span>
          ))}
        </div>
        <div className="flex gap-2">
          <input value={newHoneypotPath} onChange={e => setNewHoneypotPath(e.target.value)} placeholder="如 /admin/login.php" className="flex-1 px-3 py-1.5 bg-background border border-border rounded text-sm font-mono" onKeyDown={e => { if (e.key === "Enter") { if (newHoneypotPath.trim()) { const c = { ...config }; c.ip_access = { ...c.ip_access, honeypot_paths: [...c.ip_access.honeypot_paths, newHoneypotPath.trim()] }; setConfig(c); setNewHoneypotPath(""); } } }} />
          <button onClick={() => { if (newHoneypotPath.trim()) { const c = { ...config }; c.ip_access = { ...c.ip_access, honeypot_paths: [...c.ip_access.honeypot_paths, newHoneypotPath.trim()] }; setConfig(c); setNewHoneypotPath(""); } }} className="flex items-center gap-1 px-2 py-1 text-sm border border-border rounded hover:bg-secondary"><Plus className="w-3 h-3" /></button>
        </div>
      </div>

      {/* 登录防爆破 */}
      <div className="bg-card rounded-lg border border-border p-4 space-y-4">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-primary" />
          <h4 className="text-sm font-medium">登录防爆破</h4>
          <span className="text-xs text-muted-foreground">（同一 IP 超过限制后自动封禁）</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="block text-xs font-medium mb-1">最大尝试次数</label>
            <input type="number" min={1} max={100} value={config.login_guard.max_attempts} onChange={e => { const c = { ...config }; c.login_guard = { ...c.login_guard, max_attempts: parseInt(e.target.value) || 5 }; setConfig(c); }} className="w-full px-3 py-1.5 bg-background border border-border rounded text-sm" />
          </div>
          <div>
            <label className="block text-xs font-medium mb-1">计数窗口（分钟）</label>
            <input type="number" min={1} max={1440} value={config.login_guard.window_minutes} onChange={e => { const c = { ...config }; c.login_guard = { ...c.login_guard, window_minutes: parseInt(e.target.value) || 15 }; setConfig(c); }} className="w-full px-3 py-1.5 bg-background border border-border rounded text-sm" />
          </div>
          <div>
            <label className="block text-xs font-medium mb-1">封禁时长（分钟）</label>
            <input type="number" min={1} max={10080} value={config.login_guard.block_minutes} onChange={e => { const c = { ...config }; c.login_guard = { ...c.login_guard, block_minutes: parseInt(e.target.value) || 30 }; setConfig(c); }} className="w-full px-3 py-1.5 bg-background border border-border rounded text-sm" />
          </div>
        </div>
        <p className="text-xs text-muted-foreground">
          当前策略：同一 IP 在 {config.login_guard.window_minutes} 分钟内登录失败超过 {config.login_guard.max_attempts} 次，将封禁 {config.login_guard.block_minutes} 分钟。
        </p>
      </div>
    </div>
  );
}
