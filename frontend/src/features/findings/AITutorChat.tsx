import { useEffect, useRef, useState } from 'react';
import { BookOpen, GraduationCap, Loader2, Send, Sparkles } from 'lucide-react';
import toast from 'react-hot-toast';

import { apiErrorMessage, tutorChat } from '../../services/api';
import type { Finding, TutorChatMessage, TutorUserLevel } from '../../types';
import { Button, Select } from '../../components/ui/Primitives';

const SUGGESTED_QUESTIONS = [
  'How does an attacker exploit this vulnerability?',
  'Explain the root cause in simple terms',
  'Show me vulnerable vs secure code',
  'What standards apply to this finding?',
  'How should I test the fix?',
];

const LEVELS: Array<{ value: TutorUserLevel; label: string }> = [
  { value: 'beginner', label: 'Beginner' },
  { value: 'intermediate', label: 'Intermediate' },
  { value: 'expert', label: 'Expert' },
];

function messageId(): string {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

export function AITutorChat({ finding }: { finding: Finding }) {
  const [messages, setMessages] = useState<TutorChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [level, setLevel] = useState<TutorUserLevel>('intermediate');
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: 'smooth' });
  }, [messages, loading]);

  const send = async (text: string) => {
    const question = text.trim();
    if (!question || loading) return;
    setInput('');
    setMessages((prev) => [...prev, { id: messageId(), role: 'user', content: question, timestamp: new Date().toISOString() }]);
    setLoading(true);
    try {
      const response = await tutorChat({
        finding_id: finding.id,
        question,
        user_level: level,
      });
      setMessages((prev) => [
        ...prev,
        {
          id: messageId(),
          role: 'assistant',
          content: response.answer,
          code_examples: response.code_examples,
          references: response.references,
          follow_up_questions: response.follow_up_questions,
          timestamp: new Date().toISOString(),
        },
      ]);
    } catch (err) {
      toast.error(apiErrorMessage(err, 'The tutor could not answer right now.'));
      setMessages((prev) => [
        ...prev,
        {
          id: messageId(),
          role: 'assistant',
          content: 'I could not reach the AI tutor. Please try again in a moment.',
          timestamp: new Date().toISOString(),
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex h-[480px] flex-col overflow-hidden rounded-xl border border-[var(--border-light)] bg-[var(--surface-secondary)]">
      <div className="flex items-center justify-between border-b border-[var(--border-light)] px-4 py-2.5">
        <div className="flex items-center gap-2 text-xs font-semibold text-[var(--text-strong)]">
          <GraduationCap className="h-4 w-4 text-[var(--brand)]" />
          AI Security Tutor
        </div>
        <Select value={level} onChange={(e) => setLevel(e.target.value as TutorUserLevel)} className="w-32 !py-1 text-[11px]">
          {LEVELS.map((option) => (
            <option key={option.value} value={option.value}>{option.label}</option>
          ))}
        </Select>
      </div>

      <div ref={scrollRef} className="flex-1 space-y-3 overflow-y-auto p-4">
        {messages.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center gap-3 text-center">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-[var(--brand-soft)]">
              <BookOpen className="h-5 w-5 text-[var(--brand)]" />
            </div>
            <p className="max-w-[280px] text-xs leading-relaxed text-[var(--text-muted)]">
              Ask me anything about <span className="font-medium text-[var(--text-strong)]">{finding.title}</span> — I'll teach
              you the root cause, attack vector, and remediation.
            </p>
            <div className="flex flex-wrap justify-center gap-1.5">
              {SUGGESTED_QUESTIONS.map((question) => (
                <button
                  key={question}
                  onClick={() => send(question)}
                  className="rounded-full border border-[var(--border-default)] px-2.5 py-1 text-[10px] text-[var(--text-muted)] transition-colors hover:border-[var(--brand-soft)] hover:text-[var(--brand)]"
                >
                  {question}
                </button>
              ))}
            </div>
          </div>
        ) : (
          messages.map((message) => (
            <div key={message.id} className={`flex ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}>
              <div
                className={`max-w-[85%] rounded-xl px-3.5 py-2.5 text-xs leading-relaxed ${
                  message.role === 'user'
                    ? 'bg-[var(--brand)] text-white'
                    : 'bg-[var(--surface-primary)] text-[var(--text-default)] border border-[var(--border-light)]'
                }`}
              >
                <div className="whitespace-pre-wrap">{message.content}</div>

                {message.code_examples && message.code_examples.length > 0 ? (
                  <div className="mt-2 space-y-2">
                    {message.code_examples.map((example, index) => (
                      <div key={index} className="overflow-hidden rounded-lg border border-[var(--border-light)]">
                        <div className="flex items-center gap-1.5 border-b border-[var(--border-light)] bg-[var(--surface-secondary)] px-2.5 py-1 text-[10px] font-medium text-[var(--text-muted)]">
                          <Sparkles className="h-3 w-3 text-[var(--brand)]" />
                          {example.title || example.language}
                        </div>
                        <pre className="overflow-x-auto p-2.5 font-mono text-[10px] text-[var(--text-default)]">{example.code}</pre>
                      </div>
                    ))}
                  </div>
                ) : null}

                {message.references && message.references.length > 0 ? (
                  <div className="mt-2 flex flex-wrap gap-1">
                    {message.references.map((reference) => (
                      <span key={reference} className="rounded bg-[var(--surface-tertiary)] px-1.5 py-0.5 text-[9px] text-[var(--text-muted)]">
                        {reference}
                      </span>
                    ))}
                  </div>
                ) : null}

                {message.follow_up_questions && message.follow_up_questions.length > 0 ? (
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {message.follow_up_questions.map((followUp) => (
                      <button
                        key={followUp}
                        onClick={() => send(followUp)}
                        className="rounded-full border border-[var(--brand-soft)] px-2 py-0.5 text-[10px] text-[var(--brand)] transition-colors hover:bg-[var(--brand-soft)]"
                      >
                        {followUp}
                      </button>
                    ))}
                  </div>
                ) : null}
              </div>
            </div>
          ))
        )}

        {loading ? (
          <div className="flex justify-start">
            <div className="flex items-center gap-2 rounded-xl border border-[var(--border-light)] bg-[var(--surface-primary)] px-3.5 py-2.5 text-xs text-[var(--text-muted)]">
              <Loader2 className="h-3.5 w-3.5 animate-spin text-[var(--brand)]" />
              Teaching...
            </div>
          </div>
        ) : null}
      </div>

      <form
        onSubmit={(event) => {
          event.preventDefault();
          void send(input);
        }}
        className="flex items-center gap-2 border-t border-[var(--border-light)] p-3"
      >
        <input
          value={input}
          onChange={(event) => setInput(event.target.value)}
          placeholder="Ask the AI tutor..."
          className="flex-1 rounded-lg border border-[var(--border-default)] bg-[var(--surface-primary)] px-3 py-2 text-xs text-[var(--text-default)] outline-none placeholder:text-[var(--text-subtle)] focus:border-[var(--brand)]"
        />
        <Button type="submit" disabled={loading || !input.trim()} className="!px-2.5">
          {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Send className="h-3.5 w-3.5" />}
        </Button>
      </form>
    </div>
  );
}
