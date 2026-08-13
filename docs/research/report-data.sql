-- Source quality metrics for the Deep Research impact report.
SELECT
    1020 AS lines,
    74 AS citation_markers,
    0 AS resolvable_urls,
    0 AS reference_headings,
    '537c8c5c1fd0c016d214f21dee3b369a4838715c6fc4ae2be60690ae093bb9ac' AS normalized_sha256;

-- Status distribution of the ten high-impact claims in CLAIMS.md.
SELECT
    'Подтверждено' AS status,
    7 AS count,
    'Primary or official evidence, including scoped claims' AS meaning,
    'May support ADR/spec with scope retained' AS promotion_rule,
    '10 high-impact claims' AS review_scope
UNION ALL SELECT
    'Проектный вывод',
    2,
    'Synthesis supported by multiple sources',
    'Record as inference and review',
    '10 high-impact claims'
UNION ALL SELECT
    'Не подтверждено',
    1,
    'No resolvable evidence for project use',
    'Do not promote',
    '10 high-impact claims';

-- Accepted process impacts ordered by implementation priority.
SELECT 1 AS priority, 'Research' AS area,
       'Protocol, search log и claim ledger' AS change,
       'Прослеживаемые решения и меньше citation hallucination' AS effect
UNION ALL SELECT 2, 'SDD',
       'Evidence refs для material requirements',
       'ТЗ не наследует непроверенные claims'
UNION ALL SELECT 3, 'Evaluation',
       'Frozen datasets/metrics/baselines',
       'Меньше benchmark cherry-picking'
UNION ALL SELECT 4, 'EvidenceGraph',
       'Contradiction, uncertainty и provenance',
       'Finding становится audit-ready case file'
UNION ALL SELECT 5, 'LLM harness',
       'LLM только генерирует candidates',
       'Policy gate отделяет уверенный текст от факта';

