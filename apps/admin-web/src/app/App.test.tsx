import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import App from './App';

describe('App', () => {
  it('renders application title and system status', () => {
    render(<App />);
    expect(screen.getByText('企业隐私网关管理端')).toBeInTheDocument();
    expect(screen.getByText('系统概览')).toBeInTheDocument();
    expect(screen.getByText('网关就绪')).toBeInTheDocument();
  });
});
