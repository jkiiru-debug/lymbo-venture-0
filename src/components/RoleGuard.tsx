import React, { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react';
import { ShieldAlert, Lock, Clock, AlertTriangle, ArrowRight, RefreshCw } from 'lucide-react';

export interface StaffPermissions {
  canManageStaff?: boolean;
  canManageSettings?: boolean;
  canViewAuditLogs?: boolean;
  canReceiveStock?: boolean;
  canUploadPhotos?: boolean;
  canViewReports?: boolean;
  canManageOrders?: boolean;
  canUpdateDeliveryStatus?: boolean;
  canViewManifest?: boolean;
  canReconcileAccounts?: boolean;
  canViewSupport?: boolean;
  canDeleteOrders?: boolean;
  canEditPrices?: boolean;
  [key: string]: boolean | undefined;
}

export interface StaffUser {
  id: string;
  email: string;
  name: string;
  role: string;
  status: string;
  isApproved: boolean;
  phone?: string;
  allowedTabs: string[];
  defaultTab: string;
  permissions: StaffPermissions;
}

export interface RoleGuardContextType {
  user: StaffUser | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  error: string | null;
  allowedTabs: string[];
  permissions: StaffPermissions;
  refetchUser: () => Promise<StaffUser | null>;
  isTabAuthorized: (tab: string, requiredPermission?: string) => boolean;
}

const RoleGuardContext = createContext<RoleGuardContextType>({
  user: null,
  isLoading: true,
  isAuthenticated: false,
  error: null,
  allowedTabs: [],
  permissions: {},
  refetchUser: async () => null,
  isTabAuthorized: () => false,
});

/**
 * RoleGuardProvider: Fetches and caches server-authoritative role & permissions from /api/admin/me
 */
export const RoleGuardProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<StaffUser | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const fetchCurrentUser = useCallback(async (): Promise<StaffUser | null> => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/admin/me', {
        headers: {
          'Accept': 'application/json',
          'Cache-Control': 'no-cache',
        },
      });

      if (res.status === 401) {
        setIsAuthenticated(false);
        setUser(null);
        setIsLoading(false);
        return null;
      }

      if (!res.ok) {
        throw new Error(`Server returned HTTP ${res.status}`);
      }

      const data = await res.json();
      if (data && data.authenticated && data.user) {
        setUser(data.user);
        setIsAuthenticated(true);
        setIsLoading(false);
        return data.user;
      } else {
        setIsAuthenticated(false);
        setUser(null);
        setIsLoading(false);
        return null;
      }
    } catch (err: any) {
      console.warn('[RoleGuard] Failed to fetch server role permissions:', err.message);
      setError(err.message || 'Error communicating with authentication service.');
      setIsAuthenticated(false);
      setUser(null);
      setIsLoading(false);
      return null;
    }
  }, []);

  useEffect(() => {
    fetchCurrentUser();

    // Re-verify role whenever window gains focus or on custom portal events
    const handleReverify = () => {
      fetchCurrentUser();
    };

    window.addEventListener('focus', handleReverify);
    window.addEventListener('lymbo:session-updated', handleReverify);

    return () => {
      window.removeEventListener('focus', handleReverify);
      window.removeEventListener('lymbo:session-updated', handleReverify);
    };
  }, [fetchCurrentUser]);

  const isTabAuthorized = useCallback((tab: string, requiredPermission?: string): boolean => {
    if (!user || !user.isApproved || user.status !== 'active') {
      return false;
    }

    // Role admin has global override access
    if (user.role === 'admin') {
      return true;
    }

    // Check server-returned allowedTabs list
    const tabsList = user.allowedTabs || [];
    const hasTabAccess = tabsList.includes(tab);

    if (!hasTabAccess) {
      return false;
    }

    // If a granular permission was also requested, check it
    if (requiredPermission && user.permissions) {
      return Boolean(user.permissions[requiredPermission]);
    }

    return true;
  }, [user]);

  const value: RoleGuardContextType = {
    user,
    isLoading,
    isAuthenticated,
    error,
    allowedTabs: user?.allowedTabs || [],
    permissions: user?.permissions || {},
    refetchUser: fetchCurrentUser,
    isTabAuthorized,
  };

  return (
    <RoleGuardContext.Provider value={value}>
      {children}
    </RoleGuardContext.Provider>
  );
};

/**
 * Custom Hook: useRoleGuard
 * Provides direct access to current user role, permissions, and tab authorization check
 */
export function useRoleGuard(tab?: string, requiredPermission?: string) {
  const context = useContext(RoleGuardContext);

  const isAuthorized = tab ? context.isTabAuthorized(tab, requiredPermission) : false;

  return {
    ...context,
    isAuthorized,
  };
}

export interface RoleGuardProps {
  /** The unique tab identifier being protected (e.g. 'reports', 'inventory', 'staff', 'orders', etc.) */
  tab: string;
  /** Optional granular permission check (e.g. 'canViewReports', 'canManageStaff') */
  requiredPermission?: string;
  /** Optional custom fallback component when access is denied */
  fallback?: ReactNode;
  /** Optional callback fired when unauthorized access is prevented */
  onUnauthorized?: (reason: string) => void;
  /** The protected content to render only when verified */
  children: ReactNode;
}

/**
 * RoleGuard Component:
 * Wraps dashboard sub-tabs and verifies the user's role and approved status
 * against the server-side authorized tab list before rendering content.
 */
export const RoleGuard: React.FC<RoleGuardProps> = ({
  tab,
  requiredPermission,
  fallback,
  onUnauthorized,
  children,
}) => {
  const { user, isLoading, isAuthenticated, isTabAuthorized, refetchUser } = useContext(RoleGuardContext);

  const authorized = isTabAuthorized(tab, requiredPermission);

  useEffect(() => {
    if (!isLoading && !authorized && onUnauthorized) {
      const reason = !isAuthenticated
        ? 'unauthenticated'
        : (!user?.isApproved ? 'pending_approval' : 'role_restricted');
      onUnauthorized(reason);
    }
  }, [isLoading, authorized, isAuthenticated, user, onUnauthorized]);

  // 1. Loading State while querying server
  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center p-10 bg-slate-50 border border-slate-200 rounded-lg text-slate-500 animate-pulse my-4">
        <RefreshCw className="w-8 h-8 text-emerald-600 animate-spin mb-3" />
        <p className="text-sm font-semibold text-slate-700">Verifying Security Credentials &amp; Role Permissions...</p>
        <span className="text-xs text-slate-400 mt-1">Connecting to server authorization gateway</span>
      </div>
    );
  }

  // 2. Authorized: Render content securely
  if (authorized) {
    return <>{children}</>;
  }

  // 3. User supplied a custom fallback
  if (fallback) {
    return <>{fallback}</>;
  }

  // 4. Case: Unauthenticated
  if (!isAuthenticated || !user) {
    return (
      <div className="bg-amber-50 border-2 border-amber-300 rounded-xl p-8 text-center my-6 shadow-sm">
        <div className="inline-flex p-3 bg-amber-100 rounded-full text-amber-700 mb-3">
          <Lock className="w-8 h-8" />
        </div>
        <h3 className="text-lg font-bold text-amber-900 mb-1">Authentication Required</h3>
        <p className="text-sm text-amber-800 max-w-md mx-auto mb-4 leading-relaxed">
          The <strong>{tab.toUpperCase()}</strong> dashboard tab requires an active administrative session.
          Please sign in with your verified staff credentials and 2-factor authenticator.
        </p>
        <button
          type="button"
          onClick={() => {
            if (typeof (window as any).openAdminPortal === 'function') {
              (window as any).openAdminPortal();
            } else {
              refetchUser();
            }
          }}
          className="inline-flex items-center gap-2 px-5 py-2.5 bg-emerald-700 hover:bg-emerald-800 text-white text-sm font-bold rounded-lg transition-colors shadow"
        >
          <span>Open Staff Login</span>
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>
    );
  }

  // 5. Case: Account Pending Approval
  if (!user.isApproved || user.status !== 'active') {
    return (
      <div className="bg-amber-50 border-2 border-amber-400 rounded-xl p-8 text-center my-6 shadow-sm">
        <div className="inline-flex p-3 bg-amber-100 rounded-full text-amber-600 mb-3">
          <Clock className="w-8 h-8" />
        </div>
        <h3 className="text-lg font-bold text-amber-950 mb-1">Staff Account Pending Administrator Approval</h3>
        <p className="text-sm text-amber-900 max-w-lg mx-auto mb-3 leading-relaxed">
          Per Section 1 &amp; 2 of the Lymbo Ventures Security Architecture, job applicant and staff accounts
          must be confirmed by the System Administrator before operational dashboard tabs can be unlocked.
        </p>
        <div className="inline-block bg-white/70 border border-amber-200 text-xs px-3 py-1.5 rounded text-amber-900 font-mono mb-4">
          Status: <strong>{user.status.toUpperCase()}</strong> · Role: <strong>{user.role || 'Unassigned'}</strong>
        </div>
        <div>
          <button
            type="button"
            onClick={() => refetchUser()}
            className="inline-flex items-center gap-2 px-4 py-2 bg-amber-600 hover:bg-amber-700 text-white text-xs font-semibold rounded-lg transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Check Approval Status</span>
          </button>
        </div>
      </div>
    );
  }

  // 6. Case: Role Restricted (Least Privilege Policy)
  return (
    <div className="bg-rose-50 border-2 border-rose-300 rounded-xl p-8 text-center my-6 shadow-sm">
      <div className="inline-flex p-3 bg-rose-100 rounded-full text-rose-600 mb-3">
        <ShieldAlert className="w-8 h-8" />
      </div>
      <h3 className="text-lg font-bold text-rose-950 mb-1">Access Restricted by Role Policy</h3>
      <p className="text-sm text-rose-900 max-w-lg mx-auto mb-4 leading-relaxed">
        Your assigned position (<strong>{user.role.toUpperCase().replace('_', ' ')}</strong>) is not granted
        permission to view the <strong>{tab.toUpperCase()}</strong> dashboard tab under the least-privilege principle.
        Each position only has access to its designated functional area.
      </p>

      <div className="bg-white/80 border border-rose-200 rounded-lg p-3 max-w-md mx-auto text-left text-xs mb-5">
        <div className="flex items-center gap-1.5 font-semibold text-rose-900 mb-1">
          <AlertTriangle className="w-3.5 h-3.5 text-rose-600" />
          <span>Authorized Tabs for Your Position:</span>
        </div>
        <div className="flex flex-wrap gap-1.5 mt-1.5">
          {user.allowedTabs && user.allowedTabs.length > 0 ? (
            user.allowedTabs.map((t) => (
              <span
                key={t}
                className="px-2 py-0.5 bg-emerald-50 text-emerald-800 border border-emerald-200 rounded font-mono font-medium text-[11px]"
              >
                ✓ {t}
              </span>
            ))
          ) : (
            <span className="text-rose-500 italic">No operational tabs currently assigned</span>
          )}
        </div>
      </div>

      <div className="flex justify-center gap-3">
        {user.defaultTab && (
          <button
            type="button"
            onClick={() => {
              if (typeof (window as any).switchAdminTab === 'function') {
                (window as any).switchAdminTab(user.defaultTab);
              }
            }}
            className="inline-flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-900 text-white text-xs font-semibold rounded-lg transition-colors"
          >
            <span>Go to My Dashboard ({user.defaultTab.toUpperCase()})</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        )}
        <button
          type="button"
          onClick={() => refetchUser()}
          className="inline-flex items-center gap-2 px-3 py-2 bg-white hover:bg-rose-50 text-rose-700 border border-rose-300 text-xs font-semibold rounded-lg transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Re-verify Permissions</span>
        </button>
      </div>
    </div>
  );
};

/**
 * Higher-Order Component (HOC): withRoleGuard
 * Wraps any component and ensures the current user's role is verified against
 * the server-side authorized tab list before rendering.
 *
 * Example:
 *   const ProtectedReportsView = withRoleGuard(ReportsView, 'reports', { requiredPermission: 'canViewReports' });
 */
export function withRoleGuard<P extends object>(
  WrappedComponent: React.ComponentType<P>,
  tab: string,
  options?: {
    requiredPermission?: string;
    fallback?: ReactNode;
    onUnauthorized?: (reason: string) => void;
  }
): React.FC<P> {
  const ComponentWithRoleGuard: React.FC<P> = (props: P) => {
    return (
      <RoleGuard
        tab={tab}
        requiredPermission={options?.requiredPermission}
        fallback={options?.fallback}
        onUnauthorized={options?.onUnauthorized}
      >
        <WrappedComponent {...props} />
      </RoleGuard>
    );
  };

  const displayName = WrappedComponent.displayName || WrappedComponent.name || 'Component';
  ComponentWithRoleGuard.displayName = `withRoleGuard(${displayName}, '${tab}')`;

  return ComponentWithRoleGuard;
}

export default RoleGuard;
