import { Component, type ErrorInfo, type ReactNode } from 'react';

import { Button } from '../components/ui/Primitives';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('VulScan error boundary caught:', error, errorInfo);
  }

  handleReload = () => {
    window.location.reload();
  };

  handleGoHome = () => {
    window.location.hash = '/';
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex min-h-screen items-center justify-center bg-[var(--app-canvas)] text-[var(--text-default)]">
          <div className="max-w-md rounded-xl border border-[var(--danger-soft)] bg-[var(--danger-soft)]/20 p-6 text-center">
            <h2 className="mb-2 text-lg font-bold text-[var(--danger)]">Something went wrong</h2>
            <p className="mb-4 text-sm text-[var(--text-muted)]">
              The application encountered an unexpected error. Try reloading the page or
              returning to the dashboard.
            </p>
            {this.state.error ? (
              <pre className="mb-4 overflow-x-auto text-left text-[10px] text-[var(--text-muted)]">
                {this.state.error.message}
                {this.state.error.stack ? `\n\n${this.state.error.stack.split('\n').slice(0, 3).join('\n')}` : ''}
              </pre>
            ) : null}
            <div className="flex justify-center gap-3">
              <Button variant="secondary" onClick={this.handleGoHome}>
                Go Home
              </Button>
              <Button onClick={this.handleReload}>
                Reload
              </Button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
