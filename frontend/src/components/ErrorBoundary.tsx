import { Component, type ErrorInfo, type ReactNode } from 'react';

interface Props {
  children: ReactNode;
  title?: string;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
    errorInfo: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error, errorInfo: null };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('ErrorBoundary caught error:', error, errorInfo);
    this.setState({ error, errorInfo });
  }

  public render() {
    if (this.state.hasError) {
      return (
        <div style={{
          padding: '2rem',
          maxWidth: '820px',
          margin: '2rem auto',
          background: 'var(--panel, #131a2e)',
          color: 'var(--text, #e8ecf8)',
          borderRadius: '14px',
          border: '2px solid var(--bad, #ff6b6b)',
          boxShadow: 'var(--shadow, 0 8px 28px rgba(0,0,0,0.4))',
        }}>
          <h2 style={{ color: 'var(--bad, #ff6b6b)', marginTop: 0, display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <span>⚠️</span> UI Rendering Error Encountered
          </h2>
          <p style={{ fontSize: '1.05rem', lineHeight: '1.5' }}>
            {this.state.error?.message || 'An unexpected error occurred while rendering this view.'}
          </p>
          <pre style={{
            background: 'var(--bg, #0b1020)',
            color: 'var(--muted, #9aa6c6)',
            padding: '1rem',
            borderRadius: '8px',
            overflow: 'auto',
            fontSize: '0.85rem',
            lineHeight: '1.4',
            border: '1px solid var(--line, #2a3558)',
          }}>
            {this.state.error?.stack || 'No stack trace available.'}
          </pre>
          {this.state.errorInfo?.componentStack && (
            <details style={{ marginTop: '1rem' }}>
              <summary style={{ cursor: 'pointer', color: 'var(--accent, #5aa2ff)', fontWeight: 600 }}>
                Component Stack Trace
              </summary>
              <pre style={{
                background: 'var(--bg, #0b1020)',
                color: 'var(--muted, #9aa6c6)',
                padding: '1rem',
                borderRadius: '8px',
                overflow: 'auto',
                fontSize: '0.8rem',
                marginTop: '0.5rem',
                border: '1px solid var(--line, #2a3558)',
              }}>
                {this.state.errorInfo.componentStack}
              </pre>
            </details>
          )}
          <div style={{ marginTop: '1.5rem', display: 'flex', gap: '1rem' }}>
            <button
              onClick={() => {
                this.setState({ hasError: false, error: null, errorInfo: null });
                window.location.reload();
              }}
              style={{
                padding: '0.6rem 1.4rem',
                background: 'var(--accent, #5aa2ff)',
                color: '#0b1020',
                border: 'none',
                borderRadius: '8px',
                fontWeight: 'bold',
                cursor: 'pointer',
              }}
            >
              ↻ Reload Application
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
