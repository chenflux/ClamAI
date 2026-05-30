import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { usersApi } from "../api/users";
import { authApi } from "../api/auth";
import { isTauri } from "../api/client";
import { useCurrentUser } from "../context/UserContext";
import {
  Users,
  UserPlus,
  Trash2,
  Edit3,
  Key,
  Shield,
  ShieldCheck,
  UserX,
  Loader2,
  RefreshCw,
  ToggleLeft,
  ToggleRight,
  Copy,
  Check,
} from "lucide-react";

interface UserInfo {
  id: string;
  username: string;
  display_name: string;
  role: string;
  status: string;
  created_at: string;
  updated_at: string;
  last_login_at?: string;
}

function UserManagement() {
  const queryClient = useQueryClient();
  const { currentUser } = useCurrentUser();
  const [showCreate, setShowCreate] = useState(false);
  const [editingUser, setEditingUser] = useState<UserInfo | null>(null);
  const [resettingUserId, setResettingUserId] = useState<string | null>(null);
  const [newUser, setNewUser] = useState({ username: "", password: "", display_name: "", role: "user" });
  const [resetPassword, setResetPassword] = useState("");
  const [copied, setCopied] = useState(false);
  const [regOpen, setRegOpen] = useState(false);

  const { data: usersData, refetch } = useQuery({
    queryKey: ["users"],
    queryFn: async () => {
      const result = await usersApi.list();
      return (result.users || []) as unknown as UserInfo[];
    },
  });

  useQuery({
    queryKey: ["registration-open"],
    queryFn: async () => {
      const parsed = await authApi.status();
      setRegOpen(parsed.registration_open === true);
      return parsed;
    },
  });

  const users = usersData || [];

  const createMutation = useMutation({
    mutationFn: () =>
      usersApi.create(newUser.username, newUser.password, newUser.role, newUser.display_name || undefined),
    onSuccess: () => {
      setShowCreate(false);
      setNewUser({ username: "", password: "", display_name: "", role: "user" });
      refetch();
    },
    onError: (e: any) => alert("创建失败: " + e),
  });

  const updateMutation = useMutation({
    mutationFn: (u: UserInfo) =>
      usersApi.update(u.id, {
        display_name: u.display_name,
        role: u.role,
        is_active: u.status === "active",
        status: u.status,
      }),
    onSuccess: () => {
      setEditingUser(null);
      refetch();
    },
    onError: (e: any) => alert("更新失败: " + e),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => usersApi.delete(id),
    onSuccess: () => refetch(),
    onError: (e: any) => alert("删除失败: " + e),
  });

  const resetMutation = useMutation({
    mutationFn: ({ id, pw }: { id: string; pw: string }) =>
      usersApi.resetPassword(id, pw),
    onSuccess: () => {
      setResettingUserId(null);
      setResetPassword("");
    },
    onError: (e: any) => alert("重置失败: " + e),
  });

  const regToggleMutation = useMutation({
    mutationFn: (open: boolean) => usersApi.setRegistrationOpen(open),
    onSuccess: (_, open) => setRegOpen(open),
    onError: (e: any) => alert("设置失败: " + e),
  });

  const roleBadge = (role: string) =>
    role === "admin" ? (
      <span className="text-xs px-2 py-0.5 rounded bg-primary/10 text-primary flex items-center gap-1">
        <ShieldCheck className="w-3 h-3" />
        管理员
      </span>
    ) : (
      <span className="text-xs px-2 py-0.5 rounded bg-muted text-muted-foreground flex items-center gap-1">
        <UserX className="w-3 h-3" />
        普通用户
      </span>
    );

  const statusBadge = (status: string) =>
    status === "active" ? (
      <span className="text-xs px-2 py-0.5 rounded bg-green-500/10 text-green-500">正常</span>
    ) : (
      <span className="text-xs px-2 py-0.5 rounded bg-red-500/10 text-red-500">禁用</span>
    );

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Users className="w-6 h-6 text-primary" />
        <h2 className="text-xl font-bold">用户</h2>
        <div className="ml-auto flex items-center gap-2">
          <button
            onClick={() => refetch()}
            className="flex items-center gap-1 px-3 py-1 text-sm text-muted-foreground hover:text-foreground"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-primary text-primary-foreground rounded-lg hover:bg-primary/90"
          >
            <UserPlus className="w-4 h-4" />
            新建用户
          </button>
        </div>
      </div>

      <div className="bg-card rounded-lg border border-border p-4">
        <div className="flex items-center justify-between">
          <div>
            <h4 className="text-sm font-medium">开放注册</h4>
            <p className="text-xs text-muted-foreground mt-0.5">
              允许新用户自行注册账号，注册后为普通用户角色
            </p>
          </div>
          <button
            onClick={() => regToggleMutation.mutate(!regOpen)}
            className="flex items-center gap-2 text-sm"
          >
            {regOpen ? (
              <ToggleRight className="w-8 h-8 text-green-500" />
            ) : (
              <ToggleLeft className="w-8 h-8 text-muted-foreground" />
            )}
            <span className={regOpen ? "text-green-500" : "text-muted-foreground"}>
              {regOpen ? "已开放" : "已关闭"}
            </span>
          </button>
        </div>
        {regOpen && (
          <div className="mt-3 p-3 bg-green-500/5 border border-green-500/20 rounded-lg">
            <p className="text-sm font-medium text-green-600 dark:text-green-400">注册已开放</p>
            <p className="text-xs text-muted-foreground mt-1">
              {isTauri() ? (
                "其他用户可在本程序登录页点击「注册新账号」创建账号（仅限普通用户角色）。如需管理员请退出当前账号后查看。"
              ) : (
                <>
                  新用户可访问登录页面点击「注册新账号」创建账号（仅限普通用户角色）。
                  <span className="block mt-1.5 font-mono text-xs bg-secondary px-2 py-1 rounded select-all">
                    {window.location.origin}/admin/
                  </span>
                  <button
                    className="mt-1.5 flex items-center gap-1 text-xs text-primary hover:underline"
                    onClick={() => {
                      navigator.clipboard.writeText(`${window.location.origin}/admin/`);
                      setCopied(true);
                      setTimeout(() => setCopied(false), 2000);
                    }}
                  >
                    {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                    {copied ? "已复制" : "复制登录页地址"}
                  </button>
                </>
              )}
            </p>
          </div>
        )}
      </div>

      {showCreate && (
        <div className="bg-card rounded-lg border border-border p-4 space-y-4">
          <h4 className="text-sm font-medium">新建用户</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium mb-1">用户名</label>
              <input
                type="text"
                value={newUser.username}
                onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
                className="w-full px-3 py-2 bg-background border border-border rounded-lg text-sm"
                placeholder="登录用户名"
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">密码</label>
              <input
                type="password"
                value={newUser.password}
                onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                className="w-full px-3 py-2 bg-background border border-border rounded-lg text-sm"
                placeholder="至少6位"
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">显示名称</label>
              <input
                type="text"
                value={newUser.display_name}
                onChange={(e) => setNewUser({ ...newUser, display_name: e.target.value })}
                className="w-full px-3 py-2 bg-background border border-border rounded-lg text-sm"
                placeholder="可选"
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">角色</label>
              <select
                value={newUser.role}
                onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}
                className="w-full px-3 py-2 bg-background border border-border rounded-lg text-sm"
              >
                <option value="user">普通用户</option>
                <option value="admin">管理员</option>
              </select>
            </div>
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => createMutation.mutate()}
              disabled={!newUser.username || newUser.password.length < 6 || createMutation.isPending}
              className="px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 disabled:opacity-50 text-sm"
            >
              {createMutation.isPending ? "创建中..." : "创建"}
            </button>
            <button
              onClick={() => setShowCreate(false)}
              className="px-4 py-2 bg-secondary text-secondary-foreground rounded-lg hover:bg-secondary/80 text-sm"
            >
              取消
            </button>
          </div>
        </div>
      )}

      <div className="bg-card rounded-lg border border-border overflow-hidden">
        <div className="px-4 py-3 border-b border-border flex items-center gap-2">
          <Users className="w-4 h-4 text-primary" />
          <span className="text-sm font-medium">用户列表</span>
          <span className="text-xs text-muted-foreground ml-auto">{users.length} 个用户</span>
        </div>
        <div className="divide-y divide-border">
          {users.length === 0 && (
            <div className="px-4 py-8 text-center text-sm text-muted-foreground">暂无用户</div>
          )}
          {users.map((user) => (
            <div key={user.id} className="px-4 py-3">
              {editingUser?.id === user.id ? (
                <div className="space-y-3">
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                    <div>
                      <label className="block text-xs font-medium mb-1">显示名称</label>
                      <input
                        type="text"
                        value={editingUser.display_name}
                        onChange={(e) => setEditingUser({ ...editingUser, display_name: e.target.value })}
                        className="w-full px-3 py-1.5 bg-background border border-border rounded text-sm"
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-medium mb-1">角色</label>
                      <select
                        value={editingUser.role}
                        onChange={(e) => setEditingUser({ ...editingUser, role: e.target.value })}
                        className="w-full px-3 py-1.5 bg-background border border-border rounded text-sm"
                      >
                        <option value="user">普通用户</option>
                        <option value="admin">管理员</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-xs font-medium mb-1">状态</label>
                      <select
                        value={editingUser.status}
                        onChange={(e) => setEditingUser({ ...editingUser, status: e.target.value })}
                        className="w-full px-3 py-1.5 bg-background border border-border rounded text-sm"
                        disabled={editingUser.id === currentUser?.userId || editingUser.role === "admin"}
                      >
                        <option value="active">正常</option>
                        <option value="disabled" disabled={editingUser.id === currentUser?.userId || editingUser.role === "admin"}>禁用</option>
                      </select>
                    </div>
                  </div>
                  <div className="flex gap-2">
                    <button
                      onClick={() => updateMutation.mutate(editingUser)}
                      className="px-3 py-1 bg-primary text-primary-foreground rounded text-xs hover:bg-primary/90"
                    >
                      保存
                    </button>
                    <button
                      onClick={() => setEditingUser(null)}
                      className="px-3 py-1 bg-secondary text-secondary-foreground rounded text-xs"
                    >
                      取消
                    </button>
                  </div>
                </div>
              ) : (
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-full bg-muted flex items-center justify-center text-xs font-bold">
                    {user.display_name?.[0] || user.username[0]}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-sm">{user.display_name || user.username}</span>
                      {roleBadge(user.role)}
                      {statusBadge(user.status)}
                    </div>
                    <p className="text-xs text-muted-foreground">
                      @{user.username}
                      {user.last_login_at && ` | 上次登录: ${new Date(user.last_login_at).toLocaleString("zh-CN")}`}
                      {user.created_at && ` | 创建于: ${new Date(user.created_at).toLocaleString("zh-CN")}`}
                    </p>
                  </div>
                  <div className="flex items-center gap-1">
                    {user.status !== "active" && (
                      <button
                        onClick={() => updateMutation.mutate({ ...user, status: "active" })}
                        className="p-1.5 text-muted-foreground hover:text-emerald-500"
                        title="启用用户"
                      >
                        <ToggleRight className="w-4 h-4" />
                      </button>
                    )}
                    {user.status === "active" && user.role !== "admin" && user.id !== currentUser?.userId && (
                      <button
                        onClick={() => { if (confirm(`确定要停用用户 ${user.username} 吗？停用后该用户将无法登录。`)) updateMutation.mutate({ ...user, status: "disabled" }); }}
                        className="p-1.5 text-muted-foreground hover:text-red-500"
                        title="停用用户"
                      >
                        <ToggleLeft className="w-4 h-4" />
                      </button>
                    )}
                    <button
                      onClick={() => setEditingUser({ ...user })}
                      className="p-1.5 text-muted-foreground hover:text-primary"
                      title="编辑"
                    >
                      <Edit3 className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => { setResettingUserId(user.id); setResetPassword(""); }}
                      className="p-1.5 text-muted-foreground hover:text-orange-500"
                      title="重置密码"
                    >
                      <Key className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => { if (confirm(`确定要删除用户 ${user.username} 吗？`)) deleteMutation.mutate(user.id); }}
                      className="p-1.5 text-muted-foreground hover:text-red-500"
                      title="删除"
                      disabled={user.id === currentUser?.userId}
                    >
                      <Trash2 className={`w-4 h-4 ${user.id === currentUser?.userId ? "opacity-30 cursor-not-allowed" : ""}`} />
                    </button>
                  </div>
                </div>
              )}
              {resettingUserId === user.id && (
                <div className="mt-3 flex items-center gap-2 pl-11">
                  <input
                    type="password"
                    value={resetPassword}
                    onChange={(e) => setResetPassword(e.target.value)}
                    className="px-3 py-1.5 bg-background border border-border rounded text-sm flex-1 max-w-xs"
                    placeholder="输入新密码（至少6位）"
                  />
                  <button
                    onClick={() => resetMutation.mutate({ id: user.id, pw: resetPassword })}
                    disabled={resetPassword.length < 6}
                    className="px-3 py-1.5 bg-orange-500 text-white rounded text-xs hover:bg-orange-600 disabled:opacity-50"
                  >
                    确认重置
                  </button>
                  <button
                    onClick={() => { setResettingUserId(null); setResetPassword(""); }}
                    className="px-3 py-1.5 bg-secondary text-secondary-foreground rounded text-xs"
                  >
                    取消
                  </button>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default UserManagement;
