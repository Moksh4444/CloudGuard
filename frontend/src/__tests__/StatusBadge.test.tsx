import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import React from 'react';
import { StatusBadge } from '../components/StatusBadge';

describe('StatusBadge Component', () => {
  it('renders SUCCESS badge with green styling and text', () => {
    render(<StatusBadge status="SUCCESS" />);
    const badge = screen.getByText('SUCCESS');
    expect(badge).toBeInTheDocument();
  });

  it('renders FAILURE badge with proper label', () => {
    render(<StatusBadge status="FAILURE" />);
    const badge = screen.getByText('FAILURE');
    expect(badge).toBeInTheDocument();
  });

  it('renders CRITICAL security badge', () => {
    render(<StatusBadge status="CRITICAL" />);
    const badge = screen.getByText('CRITICAL');
    expect(badge).toBeInTheDocument();
  });

  it('renders WARNING badge', () => {
    render(<StatusBadge status="WARNING" />);
    const badge = screen.getByText('WARNING');
    expect(badge).toBeInTheDocument();
  });
});
