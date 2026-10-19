import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import React from 'react';
import { FindingCard } from '../components/FindingCard';
import { TroubleshootingFinding } from '../types';

describe('FindingCard Component', () => {
  const sampleFinding: TroubleshootingFinding = {
    symptom: 'TCP SYN packet dropped on port 5432',
    confidence: 'HIGH',
    likely_explanations: ['Security Group drops inbound TCP 5432 from client IP'],
    diagnostic_evidence: 'Handshake timed out after 5000ms',
    next_steps: ['Check AWS Security Group inbound rules'],
    limitations: 'Evaluated from scanning client perspective',
  };

  it('renders symptom and confidence level', () => {
    render(<FindingCard finding={sampleFinding} index={0} />);

    expect(screen.getByText('TCP SYN packet dropped on port 5432')).toBeInTheDocument();
    expect(screen.getByText('Confidence: HIGH')).toBeInTheDocument();
    expect(screen.getByText('Handshake timed out after 5000ms')).toBeInTheDocument();
    expect(screen.getByText('Security Group drops inbound TCP 5432 from client IP')).toBeInTheDocument();
    expect(screen.getByText('Check AWS Security Group inbound rules')).toBeInTheDocument();
  });
});
