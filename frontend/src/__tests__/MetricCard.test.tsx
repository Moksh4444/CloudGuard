import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import React from 'react';
import { Activity } from 'lucide-react';
import { MetricCard } from '../components/MetricCard';

describe('MetricCard Component', () => {
  it('renders title, value, and subtitle correctly', () => {
    render(
      <MetricCard
        title="Total Diagnostic Runs"
        value={42}
        subtitle="Last 30 days"
        icon={Activity}
        color="sky"
      />
    );

    expect(screen.getByText('Total Diagnostic Runs')).toBeInTheDocument();
    expect(screen.getByText('42')).toBeInTheDocument();
    expect(screen.getByText('Last 30 days')).toBeInTheDocument();
  });
});
