// Keyword-based first-pass contract check. It only detects visible clauses; it is not legal advice.
export const LEGAL_CLAUSES = [
  { key: 'الأطراف', pattern: /الأطراف|الطرف الأول|الطرف الثاني|المتعاقد|parties|first party/i },
  { key: 'نطاق العمل والالتزامات', pattern: /الالتزامات|نطاق العمل|الخدمات|المهام|obligations|scope of work/i },
  { key: 'المقابل وآلية الدفع', pattern: /المبلغ|المقابل|ريال|الدفع|الأجرة|payment|fee|amount|sar/i },
  { key: 'المدة والتواريخ', pattern: /المدة|تاريخ|سنة|شهر|يوم|ينتهي|term|duration|date/i },
  { key: 'الإنهاء والفسخ', pattern: /الإنهاء|إنهاء|فسخ|إلغاء|termination|cancel/i },
  { key: 'حل النزاعات والاختصاص', pattern: /نزاع|النزاعات|المحكمة|الاختصاص|التحكيم|dispute|jurisdiction/i },
  { key: 'التوقيع', pattern: /التوقيع|توقيع|التواقيع|signature|signed/i },
];

export function analyzeContract(content: string) {
  const clauses = LEGAL_CLAUSES.map(({ key, pattern }) => ({ name: key, present: pattern.test(content) }));
  const presentCount = clauses.filter((clause) => clause.present).length;
  return {
    score: Math.round((presentCount / clauses.length) * 100),
    clauses,
    risks: clauses.filter((clause) => !clause.present).map((clause) => `لم يتم العثور على بند واضح: ${clause.name}`),
    disclaimer:
      'فحص أولي للكلمات والبنود الظاهرة فقط؛ لا يمثل استشارة قانونية أو حكماً بالامتثال للأنظمة السعودية. راجع محامياً مرخصاً.',
  };
}

// Prevents spreadsheet formula injection when the CSV is opened in Excel/Sheets.
export function csvCell(value: unknown): string {
  let safeValue = String(value ?? '');
  if (/^[=+\-@\t\r]/.test(safeValue)) safeValue = `'${safeValue}`;
  return `"${safeValue.replaceAll('"', '""')}"`;
}
