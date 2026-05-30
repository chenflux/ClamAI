import React, {
  createContext,
  useContext,
  useState,
  useCallback,
  useEffect,
} from "react";
import { authApi, handleLoginResult } from "../api/auth";
import { isTauri } from "../api/client";

interface AuthContextType {
  token: string | null;
  isAuthenticated: boolean;
  isInitialized: boolean;
  initialized: boolean;
  mode: string;
  registrationOpen: boolean;
  login: (username: string, password: string) => Promise<void>;
  setup: (username: string, password: string) => Promise<void>;
  register: (username: string, password: string, displayName?: string) => Promise<void>;
  logout: () => void;
  changePassword: (oldPassword: string, newPassword: string) => Promise<void>;
  handleAuthExpired: () => void;
  refreshAuth: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [token, setToken] = useState<string | null>(() => {
    return localStorage.getItem("clamai_token");
  });
  const [isInitialized, setIsInitialized] = useState(false);
  const [initialized, setInitialized] = useState(false);
  const [mode, setMode] = useState("pc");
  const [registrationOpen, setRegistrationOpen] = useState(false);

  useEffect(() => {
    checkStatus();
  }, []);

  useEffect(() => {
    if (token) {
      localStorage.setItem("clamai_token", token);
    } else {
      localStorage.removeItem("clamai_token");
    }
  }, [token]);

  useEffect(() => {
    const handler = () => {
      setToken(null);
      localStorage.removeItem("clamai_token");
    };
    window.addEventListener("auth:unauthorized", handler);
    return () => window.removeEventListener("auth:unauthorized", handler);
  }, []);

  const checkStatus = async (skipAutoLogin?: boolean) => {
    try {
      const status = await authApi.status();
      setInitialized(status.initialized);
      setMode(status.mode);
      setRegistrationOpen(status.registration_open === true);
      setIsInitialized(true);

      if (!skipAutoLogin && status.mode === "pc" && status.initialized && !token) {
        tryAutoLogin();
      }
    } catch (e) {
      console.error("[AuthContext] checkStatus FAILED:", e);
      setIsInitialized(true);
    }
  };

  const tryAutoLogin = async () => {
    try {
      const accessToken = await authApi.tryAutoLogin();
      if (accessToken) {
        setToken(accessToken);
      }
    } catch (_e) {}
  };

  const login = useCallback(async (username: string, password: string) => {
    const result = await authApi.login(username, password);
    const accessToken = handleLoginResult(result);
    setToken(accessToken);
  }, []);

  const handleAuthExpired = useCallback(() => {
    setToken(null);
    localStorage.removeItem("clamai_token");
  }, []);

  const setupAdmin = useCallback(async (username: string, password: string) => {
    const result = await authApi.setup(username, password);
    const accessToken = handleLoginResult(result);
    setToken(accessToken);
    localStorage.setItem("clamai_token", accessToken);
    setInitialized(true);
  }, []);

  const register = useCallback(async (username: string, password: string, displayName?: string) => {
    const result = await authApi.register(username, password, displayName);
    if (result.access_token) {
      const accessToken = handleLoginResult(result);
      setToken(accessToken);
    } else {
      throw new Error("注册失败");
    }
  }, []);

  const logout = useCallback(() => {
    authApi.logout();
    setToken(null);
    localStorage.removeItem("clamai_token");
    checkStatus(true);
  }, []);

  const changePassword = useCallback(
    async (oldPassword: string, newPassword: string) => {
      await authApi.changePassword(oldPassword, newPassword);
    },
    [token],
  );

  const refreshAuth = useCallback(async () => {
    await checkStatus();
  }, [checkStatus]);

  return (
    <AuthContext.Provider
      value={{
        token,
        isAuthenticated: !!token,
        isInitialized,
        initialized,
        mode,
        registrationOpen,
        login,
        setup: setupAdmin,
        register,
        logout,
        changePassword,
        handleAuthExpired,
        refreshAuth,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return context;
}
