import { motion } from 'framer-motion';
import { ArrowRight, Bug, CheckCircle2, Loader2, ShieldCheck, ShieldOff, Target } from 'lucide-react';

import type { JobEvent } from '../../types';

interface FlowStep {
  label: string;
  icon: any;
  color: string;
  active: boolean;
  result?: 'pass' | 'finding' | 'blocked' | 'error';
}

function getFlowSteps(events: JobEvent[]): FlowStep[] {
  const hasFinding = events.some((e) => e.event_type === 'FINDING_DETECTED');
  const hasBlocked = events.some((e) => e.event_type === 'CONTROL_BLOCKED_TEST');
  const hasError = events.some((e) => e.event_type === 'MODULE_FAILED' || (e.event_type === 'JOB_COMPLETED' && e.status === 'FAILED'));
  const isRunning = events.some((e) => e.event_type === 'MODULE_STARTED') && !events.some((e) => e.event_type === 'JOB_COMPLETED');
  const moduleRunning = events.some((e) => e.event_type === 'MODULE_STARTED');
  const testSent = events.some((e) => e.event_type === 'TEST_REQUEST_SENT');
  const responseReceived = events.some((e) => e.event_type === 'RESPONSE_RECEIVED');
  const controlEvaluated = events.some((e) => e.event_type === 'SECURITY_CONTROL_EVALUATED');

  return [
    {
      label: 'VulScan',
      icon: Bug,
      color: 'text-[var(--accent-hover)]',
      active: true,
    },
    {
      label: 'Test',
      icon: testSent || responseReceived ? CheckCircle2 : isRunning ? Loader2 : ArrowRight,
      color: testSent || responseReceived ? 'text-[var(--success)]' : 'text-[var(--text-muted)]',
      active: testSent || responseReceived || moduleRunning,
      result: testSent || responseReceived ? 'pass' : undefined,
    },
    {
      label: 'Surface',
      icon: Target,
      color: responseReceived ? 'text-[var(--warning)]' : 'text-[var(--text-muted)]',
      active: responseReceived || controlEvaluated,
      result: responseReceived ? 'pass' : undefined,
    },
    {
      label: 'Control',
      icon: hasBlocked ? ShieldOff : controlEvaluated ? ShieldCheck : ShieldCheck,
      color: hasBlocked ? 'text-[var(--success)]' : hasFinding ? 'text-[var(--error)]' : controlEvaluated ? 'text-[var(--accent-hover)]' : 'text-[var(--text-muted)]',
      active: controlEvaluated || hasFinding || hasBlocked,
      result: hasFinding ? 'finding' : hasBlocked ? 'blocked' : undefined,
    },
    {
      label: 'Result',
      icon: hasFinding ? Bug : hasBlocked ? CheckCircle2 : hasError ? Loader2 : ArrowRight,
      color: hasFinding ? 'text-[var(--error)]' : hasBlocked ? 'text-[var(--success)]' : hasError ? 'text-[var(--error)]' : 'text-[var(--text-muted)]',
      active: events.length > 0,
      result: hasFinding ? 'finding' : hasBlocked ? 'pass' : hasError ? 'error' : undefined,
    },
  ];
}

export default function AttackFlowAnimation({ events }: { events: JobEvent[] }) {
  const steps = getFlowSteps(events);

  return (
    <div className="flex items-center justify-center gap-0.5 py-1.5 overflow-x-auto">
      {steps.map((step, index) => (
        <div key={step.label} className="flex items-center gap-0.5 shrink-0">
          <motion.div
            className={`flex items-center gap-1 rounded-md px-2 py-1 text-[10px] font-semibold transition-colors ${
              step.active ? 'bg-[var(--bg-hover)] text-[var(--text-primary)]' : 'text-[var(--text-disabled)]'
            }`}
            initial={false}
            animate={step.active && step.label === 'VulScan' ? { scale: [1, 1.02, 1] } : {}}
            transition={{ duration: 2, repeat: Infinity, repeatDelay: 1, ease: 'easeInOut' }}
          >
            <step.icon className={`h-3 w-3 ${step.color}`} />
            <span>{step.label}</span>
            {step.result === 'finding' ? (
              <span className="rounded bg-[var(--error-subtle)] px-1 py-0.5 text-[8px] text-[var(--error)]">FINDING</span>
            ) : step.result === 'pass' || step.result === 'blocked' ? (
              <span className="rounded bg-[var(--success-subtle)] px-1 py-0.5 text-[8px] text-[var(--success)]">
                {step.result === 'pass' ? 'PASS' : 'BLOCKED'}
              </span>
            ) : step.result === 'error' ? (
              <span className="rounded bg-[var(--error-subtle)] px-1 py-0.5 text-[8px] text-[var(--error)]">ERROR</span>
            ) : null}
          </motion.div>
          {index < steps.length - 1 ? <ArrowRight className="h-3 w-3 shrink-0 text-[var(--text-disabled)]" /> : null}
        </div>
      ))}
    </div>
  );
}
