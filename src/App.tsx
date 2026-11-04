import React, { useState, useEffect } from 'react';
import { createPortal } from 'react-dom';
import DailyOrdersLineChart from './components/DailyOrdersLineChart';
import { RoleGuardProvider, RoleGuard, withRoleGuard, useRoleGuard } from './components/RoleGuard';

// Higher-order component wrapping the Sales Reports sub-tab chart
const ProtectedDailyOrdersLineChart = withRoleGuard(DailyOrdersLineChart, 'reports', {
  requiredPermission: 'canViewReports',
});

// Complete registry of all admin dashboard sub-tabs and their DOM pane IDs
const SUB_TAB_PANE_MAP: Record<string, string> = {
  inventory: 'adminTabInventoryPane',
  orders: 'adminTabOrdersPane',
  dispatch: 'adminTabDispatchPane',
  accounts: 'adminTabAccountsPane',
  support: 'adminTabSupportPane',
  staff: 'adminTabStaffPane',
  reports: 'adminTabReportsPane',
  photos: 'adminTabPhotosPane',
  restock: 'adminTabRestockPane',
  settings: 'adminTabSettingsPane',
  logs: 'adminTabLogsPane',
};

/**
 * AdminSubTabGuards:
 * Verifies the current user's role and approved status against the server-side
 * authorized tab list for every active sub-tab before rendering content.
 */
function AdminSubTabGuards() {
  const { isLoading, isTabAuthorized } = useRoleGuard();
  const [activeTab, setActiveTab] = useState<string>('orders');
  const [targetPane, setTargetPane] = useState<HTMLElement | null>(null);

  useEffect(() => {
    const handleTabChange = (e: any) => {
      const tab = e?.detail?.tab;
      if (tab) {
        setActiveTab(tab);
      }
    };

    window.addEventListener('lymbo:tab-changed', handleTabChange);

    // Initial detection of active tab from DOM panes
    const detectActiveTab = () => {
      for (const [tabKey, paneId] of Object.entries(SUB_TAB_PANE_MAP)) {
        const pane = document.getElementById(paneId);
        if (pane && pane.style.display !== 'none') {
          setActiveTab(tabKey);
          setTargetPane(pane);
          return;
        }
      }
    };

    detectActiveTab();
    const interval = setInterval(detectActiveTab, 1000);

    return () => {
      window.removeEventListener('lymbo:tab-changed', handleTabChange);
      clearInterval(interval);
    };
  }, []);

  useEffect(() => {
    const paneId = SUB_TAB_PANE_MAP[activeTab];
    if (paneId) {
      setTargetPane(document.getElementById(paneId));
    }
  }, [activeTab]);

  const isAuthorized = isTabAuthorized(activeTab);

  if (!targetPane) return null;

  return (
    <>
      {!isAuthorized && !isLoading ? (
        createPortal(
          <div
            id="adminTabRoleGuardShield"
            style={{
              position: 'relative',
              zIndex: 50,
              width: '100%',
              margin: '1rem 0',
            }}
          >
            <RoleGuard tab={activeTab}>
              <div />
            </RoleGuard>
          </div>,
          targetPane
        )
      ) : null}
    </>
  );
}

export default function App() {
  const [chartContainer, setChartContainer] = useState<HTMLElement | null>(null);

  useEffect(() => {
    const findContainer = () => {
      const el = document.getElementById('adminSalesChartRoot');
      if (el) {
        setChartContainer(el);
        return true;
      }
      return false;
    };

    if (!findContainer()) {
      const interval = setInterval(() => {
        if (findContainer()) {
          clearInterval(interval);
        }
      }, 100);
      return () => clearInterval(interval);
    }
  }, []);

  return (
    <RoleGuardProvider>
      <AdminSubTabGuards />
      {chartContainer
        ? createPortal(<ProtectedDailyOrdersLineChart />, chartContainer)
        : null}
    </RoleGuardProvider>
  );
}
