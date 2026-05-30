import { apiRequest } from "./client";

export interface UserInfo {
  id: string;
  username: string;
  role: string;
  display_name: string;
  created_at: string;
  last_login: string | null;
  is_active: boolean;
}

export interface UserListResult {
  users: UserInfo[];
}

export const usersApi = {
  list: () => apiRequest<UserListResult>("GET", "/users"),

  create: (username: string, password: string, role: string = "user", displayName?: string) =>
    apiRequest<void>("POST", "/users", { username, password, role, display_name: displayName }),

  update: (id: string, data: { role?: string; display_name?: string; is_active?: boolean; status?: string }) =>
    apiRequest<void>("PUT", `/users/${id}`, data),

  delete: (id: string) =>
    apiRequest<void>("DELETE", `/users/${id}`),

  resetPassword: (id: string, newPassword: string) =>
    apiRequest<void>("POST", `/users/${id}/reset-password`, { new_password: newPassword }),

  setRegistrationOpen: (open: boolean) =>
    apiRequest<void>("PUT", "/users/settings/registration", { registration_open: open }),
};
