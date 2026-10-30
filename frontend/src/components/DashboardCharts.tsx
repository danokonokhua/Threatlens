'use client';

import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, LineChart, Line } from 'recharts';

interface ChartData {
  indicators: any[];
  alerts: any[];
}

const COLORS = ['#ef4444', '#f97316', '#eab308', '#3b82f6']; // Red, Orange, Yellow, Blue

export function SeverityDistribution({ alerts }: { alerts: any[] }) {
  const severityData = [
    { name: 'Critical', value: alerts.filter(a => a.severity === 'critical').length },
    { name: 'High', value: alerts.filter(a => a.severity === 'high').length },
    { name: 'Medium', value: alerts.filter(a => a.severity === 'medium').length },
    { name: 'Low', value: alerts.filter(a => a.severity === 'low').length },
  ].filter(item => item.value > 0); // Only show categories with data

  if (severityData.length === 0) {
    return <div className="text-gray-400 text-center py-8">No alert severity data</div>;
  }

  return (
    <div className="bg-gray-900 border border-gray-800 p-4 rounded-xl">
      <h3 className="text-lg font-semibold text-gray-200 mb-4">Alert Severity Distribution</h3>
      <ResponsiveContainer width="100%" height={250}>
        <PieChart>
          <Pie
            data={severityData}
            cx="50%"
            cy="50%"
            labelLine={false}
            label={({ name, percent }) => `${name}: ${((percent || 0) * 100).toFixed(0)}%`}
            outerRadius={80}
            fill="#8884d8"
            dataKey="value"
          >
            {severityData.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
            ))}
          </Pie>
          <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: 'none', borderRadius: '8px' }} />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}

export function AlertTrends({ alerts }: { alerts: any[] }) {
  const statusData = [
    { name: 'New', count: alerts.filter(a => a.status === 'new').length },
    { name: 'Acknowledged', count: alerts.filter(a => a.status === 'acknowledged').length },
    { name: 'In Progress', count: alerts.filter(a => a.status === 'in-progress').length },
    { name: 'Resolved', count: alerts.filter(a => a.status === 'resolved').length },
  ].filter(item => item.count > 0);

  if (statusData.length === 0) {
    return <div className="text-gray-400 text-center py-8">No alert trend data</div>;
  }

  return (
    <div className="bg-gray-900 border border-gray-800 p-4 rounded-xl">
      <h3 className="text-lg font-semibold text-gray-200 mb-4">Alert Status Breakdown</h3>
      <ResponsiveContainer width="100%" height={250}>
        <BarChart data={statusData}>
          <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
          <XAxis dataKey="name" stroke="#9ca3af" />
          <YAxis stroke="#9ca3af" />
          <Tooltip 
            contentStyle={{ backgroundColor: '#1f2937', border: 'none', borderRadius: '8px' }}
            itemStyle={{ color: '#e5e7eb' }}
          />
          <Bar dataKey="count" fill="#3b82f6" radius={[4, 4, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

export function IndicatorTypes({ indicators }: { indicators: any[] }) {
  const typeCounts = indicators.reduce((acc, ind) => {
    acc[ind.type] = (acc[ind.type] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const typeData = Object.entries(typeCounts).map(([type, count]) => ({
    name: type.charAt(0).toUpperCase() + type.slice(1),
    value: count,
  }));

  if (typeData.length === 0) {
    return <div className="text-gray-400 text-center py-8">No indicator type data</div>;
  }

  return (
    <div className="bg-gray-900 border border-gray-800 p-4 rounded-xl">
      <h3 className="text-lg font-semibold text-gray-200 mb-4">Indicator Types</h3>
      <ResponsiveContainer width="100%" height={250}>
        <PieChart>
          <Pie
            data={typeData}
            cx="50%"
            cy="50%"
            labelLine={false}
            label={({ name, value }) => `${name}: ${value}`}
            outerRadius={80}
            fill="#8884d8"
            dataKey="value"
          >
            {typeData.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
            ))}
          </Pie>
          <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: 'none', borderRadius: '8px' }} />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}