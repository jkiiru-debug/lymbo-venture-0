import React, { useState, useEffect } from 'react';
import { createPortal } from 'react-dom';
import DailyOrdersLineChart from './components/DailyOrdersLineChart';

export default function App() {
  const [chartContainer, setChartContainer] = useState<HTMLElement | null>(null);

  useEffect(() => {
    // Attempt to locate the Recharts container inside the Sales Reports tab
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
    <>
      {chartContainer ? createPortal(<DailyOrdersLineChart />, chartContainer) : null}
    </>
  );
}
