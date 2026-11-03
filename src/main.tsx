import React, { useEffect, useState } from 'react';
import ReactDOM from 'react-dom/client';
import { invoke } from '@tauri-apps/api/core';
import {
  Activity,
  AlertTriangle,
  BookOpen,
  Check,
  Download,
  Edit3,
  FileText,
  FolderKanban,
  Gauge,
  GitBranch,
  LayoutDashboard,
  Play,
  Radar,
  Settings,
  ShieldAlert,
  Sparkles,
  Upload,
  X
} from 'lucide-react';
import './styles.css';

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

type Finding = {
  id: string;
  scan_id?: string;
  severity: Severity;
  title: string;
  endpoint: string;
  confidence: string;
  status: string;
  parameter_name?: string | null;
  evidence_json?: string;
  remediation?: string;
  cwe?: string | null;
  owasp_category?: string | null;
  dedupe_key?: string | null;
  created_at?: string;
  updated_at?: string;
};

type FindingStatus = 'new' | 'open' | 'accepted_risk' | 'false_positive' | 'resolved';

type FindingSeverityFilter = Severity | 'all';
type FindingStatusFilter = FindingStatus | 'all';
type FindingSortKey = 'severity' | 'status' | 'updated';
type ReportFormat = 'html' | 'markdown' | 'json' | 'pdf' | 'sarif';
type AiProvider = 'openai' | 'anthropic' | 'custom';

type ReportArtifactMetadata = {
  fileName: string;
};

type ReportArtifactRecord = {
  file_name: string;
  relative_path: string;
  size_bytes: number;
  sha256: string;
};

type ReportExportResult = {
  usage: UsageSnapshot;
  artifact: ReportArtifactRecord;
};

type CleanupReportArtifactsResult = {
  deleted_count: number;
  deleted_bytes: number;
};

type SupportDiagnosticsResult = {
  file_name: string;
  relative_path: string;
  size_bytes: number;
  sha256: string;
  generated_at: string;
};

type RulePackStatus = {
  version: string;
  channel: string;
  source: string;
  rule_count: number;
  enabled_rule_count: number;
  disabled_rule_count: number;
  published_at: string | null;
  imported_at: string | null;
  manifest_sha256: string | null;
  bundle_sha256: string | null;
  bundle_size_bytes: number | null;
  bundle_file_name: string | null;
  rollback_available: boolean;
};

type RulePackUpdateFeedStatus = {
  current_version: string;
  latest_version: string;
  channel: string;
  update_available: boolean;
  entitlement_allowed: boolean;
  blocked_reason: string | null;
  manifest_sha256: string;
  manifest_url: string | null;
  published_at: string | null;
  minimum_app_version: string | null;
  signature_verified: boolean;
};

type RulePackBundleFile = {
  name: string;
  size: number;
  bytes: number[];
};

type SecretSnapshot = {
  provider: string;
  account: string;
  masked_value: string;
};

type AiFixGuideInput = {
  finding_id: string;
  title: string;
  severity: Severity;
  endpoint: string;
  evidence: unknown;
  remediation_hint: string;
};

type AiFixGuide = {
  finding_id: string;
  summary: string;
  safe_fix_steps: string[];
  verification_steps: string[];
  cautions: string[];
};

type EngineStatus = 'stopped' | 'starting' | 'ready' | 'degraded';

type EngineCheck = {
  component: string;
  status: 'ready' | 'pending' | 'degraded';
  message: string;
};

type EngineSnapshot = {
  status: EngineStatus;
  version: string;
  bind_address: string;
  active_scans: number;
  max_concurrent_scans: number;
  checks: EngineCheck[];
};

type LocalStorageSnapshot = {
  database_path: string;
  applied_migrations: string[];
  workspace_count: number;
  project_count: number;
  target_count: number;
};

type UsageSnapshot = {
  monthly_scans: number;
  projects: number;
  targets: number;
  reports: number;
  ai_fix_guides: number;
  active_scans: number;
};

type AuditLogRecord = {
  id: string;
  actor_user_id: string | null;
  action: string;
  entity_type: string;
  entity_id: string;
  severity: string;
  metadata_json_redacted: string;
  created_at: string;
};

type ProjectRecord = {
  id: string;
  name: string;
  description: string;
  status: string;
  target_count: number;
  created_at: string;
  updated_at: string;
};

type TargetRecord = {
  id: string;
  project_id: string;
  target_type: string;
  name: string;
  url: string;
  approval_note: string;
  allow_private_network: boolean;
  status: string;
  created_at: string;
  updated_at: string;
};

type OpenApiParameter = {
  name: string;
  location: string;
  required: boolean;
};

type OpenApiEndpoint = {
  method: string;
  path: string;
  url: string;
  operation_id: string | null;
  parameters: OpenApiParameter[];
  tags: string[];
  security_requirements: string[];
};

type OpenApiImportResult = {
  title: string | null;
  version: string | null;
  base_url: string;
  endpoints: OpenApiEndpoint[];
};

type UrlSeed = {
  url: string;
};

type UrlSeedImportResult = {
  seed_count: number;
  skipped_count: number;
  seeds: UrlSeed[];
};

type CrawlCandidate = {
  method: string;
  url: string;
  source: 'anchor_href' | 'form_action' | 'script_src' | 'link_href' | 'browser_route' | 'browser_request';
  parameters: CrawlParameter[];
};

type CrawlParameter = {
  name: string;
  location: 'query' | 'body';
  required: boolean;
};

type CrawlPage = {
  url: string;
  depth: number;
  status_code: number;
  candidate_count: number;
};

type UrlCrawlResult = {
  seed_url: string;
  page_count: number;
  candidate_count: number;
  pages: CrawlPage[];
  candidates: CrawlCandidate[];
};

type BrowserCrawlResult = {
  base_url: string;
  candidate_count: number;
  candidates: CrawlCandidate[];
};

type TargetEndpointRecord = {
  id: string;
  target_id: string;
  method: string;
  path: string;
  url: string;
  operation_id: string | null;
  parameters_json: string;
  status: string;
  created_at: string;
  updated_at: string;
};

type ScanRecord = {
  id: string;
  project_id: string;
  target_id: string;
  project_name: string;
  target_name: string;
  target_url: string;
  profile: 'safe' | 'passive' | 'surface';
  phase: string;
  status_message: string;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
  updated_at: string;
};

type BaselineDiffSummary = {
  scan_id: string;
  baseline_scan_id: string | null;
  new_findings: Finding[];
  recurring_findings: Finding[];
  resolved_findings: Finding[];
};

type ScanRunnerStatus = {
  enabled: boolean;
};

type ProjectFormState = {
  id?: string;
  name: string;
  description: string;
};

type ScanFormState = {
  project_id: string;
  target_id: string;
  profile: 'safe' | 'passive' | 'surface';
};

type TargetFormState = {
  id?: string;
  project_id: string;
  target_type: 'url' | 'api' | 'openapi';
  name: string;
  url: string;
  approval_note: string;
  allow_private_network: boolean;
};

const previewEngine: EngineSnapshot = {
  status: 'ready',
  version: '0.1.0',
  bind_address: '127.0.0.1',
  active_scans: 0,
  max_concurrent_scans: 1,
  checks: [
    {
      component: 'scope_validator',
      status: 'ready',
      message: 'approved target policy loaded'
    },
    {
      component: 'local_api',
      status: 'ready',
      message: 'desktop preview fallback'
    }
  ]
};

const previewStorage: LocalStorageSnapshot = {
  database_path: 'browser-preview',
  applied_migrations: ['0001_initial_local_store'],
  workspace_count: 1,
  project_count: 0,
  target_count: 0
};

const previewUsage: UsageSnapshot = {
  monthly_scans: 2,
  projects: 1,
  targets: 1,
  reports: 3,
  ai_fix_guides: 0,
  active_scans: 0
};

const previewProjects: ProjectRecord[] = [
  {
    id: 'project-preview',
    name: 'Staging Web',
    description: 'Preview project for the desktop shell',
    status: 'active',
    target_count: 1,
    created_at: '2026-06-12T00:00:00Z',
    updated_at: '2026-06-12T00:00:00Z'
  }
];

const previewTargets: TargetRecord[] = [
  {
    id: 'target-preview',
    project_id: 'project-preview',
    target_type: 'url',
    name: 'Staging App',
    url: 'https://staging.example.com',
    approval_note: 'Owner approval captured in preview mode',
    allow_private_network: false,
    status: 'active',
    created_at: '2026-06-12T00:00:00Z',
    updated_at: '2026-06-12T00:00:00Z'
  }
];

const previewScans: ScanRecord[] = [
  {
    id: 'scan-preview',
    project_id: 'project-preview',
    target_id: 'target-preview',
    project_name: 'Staging Web',
    target_name: 'Staging App',
    target_url: 'https://staging.example.com',
    profile: 'safe',
    phase: 'queued',
    status_message: 'Waiting for Local Engine Service',
    started_at: null,
    finished_at: null,
    created_at: '2026-06-12T00:00:00Z',
    updated_at: '2026-06-12T00:00:00Z'
  }
];

const previewFindings: Finding[] = [
  {
    id: 'F-1024',
    severity: 'high',
    title: 'Reflected XSS signal in query parameter',
    endpoint: 'GET /search?q={payload}',
    confidence: 'High',
    status: 'New'
  },
  {
    id: 'F-1025',
    severity: 'medium',
    title: 'Missing Content-Security-Policy header',
    endpoint: 'GET /',
    confidence: 'Medium',
    status: 'Open'
  },
  {
    id: 'F-1026',
    severity: 'low',
    title: 'Server version disclosure',
    endpoint: 'GET /api/health',
    confidence: 'High',
    status: 'Accepted Risk'
  }
];

const emptyProjectForm: ProjectFormState = {
  name: '',
  description: ''
};

const emptyTargetForm: TargetFormState = {
  project_id: '',
  target_type: 'url',
  name: '',
  url: '',
  approval_note: '',
  allow_private_network: false
};

const emptyScanForm: ScanFormState = {
  project_id: '',
  target_id: '',
  profile: 'safe'
};

const maxOpenApiDocumentChars = 2 * 1024 * 1024;
const maxUrlSeedDocumentChars = 512 * 1024;
const maxHtmlDocumentChars = 2 * 1024 * 1024;
const maxBrowserObservationDocumentChars = 2 * 1024 * 1024;

const sampleOpenApiDocument = `openapi: 3.0.3
info:
  title: Sample API
  version: 1.0.0
servers:
  - url: https://api.example.com
paths:
  /health:
    get:
      operationId: health`;

const sampleUrlSeedDocument = `# Approved URLs
https://example.com/
https://example.com/admin
https://api.example.com/v1/health`;

const sampleHtmlDocument = `<html>
  <body>
    <a href="/dashboard">Dashboard</a>
    <form action="/login" method="post"></form>
    <script src="/assets/app.js"></script>
  </body>
</html>`;

const sampleBrowserObservationDocument = `{
  "routes": [
    "https://example.com/app/dashboard?tab=profile"
  ],
  "requests": [
    {
      "method": "GET",
      "url": "https://example.com/api/users?search=alice",
      "resource_type": "xhr"
    },
    {
      "method": "POST",
      "url": "https://example.com/api/session",
      "resource_type": "fetch"
    }
  ]
}`;

const sampleRulePackManifest = `{
  "version": "2026.06.24-local",
  "channel": "local",
  "published_at": "2026-06-24T00:00:00Z",
  "rules": [
    {
      "id": "passive.missing_csp",
      "severity": "high",
      "enabled": true
    },
    {
      "id": "surface.exposed_env_file",
      "severity": "high",
      "enabled": false
    }
  ]
}`;

const sampleRulePackUpdateFeed = `{
  "latest_version": "2026.06.24-local",
  "channel": "local",
  "published_at": "2026-06-24T00:00:00Z",
  "minimum_app_version": "0.1.0",
  "manifest_url": "https://updates.example.com/aegis/rules/2026.06.24-local/manifest.json",
  "manifest_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "signature": ""
}`;

const maxRulePackBundleBytes = 10 * 1024 * 1024;

const navItems = [
  { label: 'Dashboard', icon: LayoutDashboard, active: true },
  { label: 'Onboarding', icon: Activity },
  { label: 'Projects', icon: FolderKanban },
  { label: 'Scans', icon: Radar },
  { label: 'Findings', icon: ShieldAlert },
  { label: 'AI Fix Guide', icon: Sparkles },
  { label: 'Reports', icon: FileText },
  { label: 'CI/CD Gate', icon: GitBranch },
  { label: 'Knowledge Base', icon: BookOpen },
  { label: 'Settings', icon: Settings }
];

async function readTextFile(file: File, maxChars: number): Promise<string> {
  if (file.size > maxChars) {
    throw new Error(`File is larger than ${formatBytes(maxChars)}.`);
  }
  const text = await file.text();
  if (text.length > maxChars) {
    throw new Error(`File content is larger than ${formatBytes(maxChars)}.`);
  }
  return text;
}

async function readBinaryFile(file: File, maxBytes: number): Promise<number[]> {
  if (file.size > maxBytes) {
    throw new Error(`File is larger than ${formatBytes(maxBytes)}.`);
  }
  const buffer = await file.arrayBuffer();
  if (buffer.byteLength > maxBytes) {
    throw new Error(`File content is larger than ${formatBytes(maxBytes)}.`);
  }
  return Array.from(new Uint8Array(buffer));
}

function App() {
  const [engine, setEngine] = useState<EngineSnapshot>(previewEngine);
  const [storage, setStorage] = useState<LocalStorageSnapshot>(previewStorage);
  const [usage, setUsage] = useState<UsageSnapshot>(previewUsage);
  const [rulePackStatus, setRulePackStatus] = useState<RulePackStatus | null>(null);
  const [projects, setProjects] = useState<ProjectRecord[]>(previewProjects);
  const [targets, setTargets] = useState<TargetRecord[]>(previewTargets);
  const [targetEndpoints, setTargetEndpoints] = useState<TargetEndpointRecord[]>([]);
  const [scans, setScans] = useState<ScanRecord[]>(previewScans);
  const [baselineDiffs, setBaselineDiffs] = useState<Record<string, BaselineDiffSummary>>({});
  const [findings, setFindings] = useState<Finding[]>(previewFindings);
  const [auditLogs, setAuditLogs] = useState<AuditLogRecord[]>([]);
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(previewFindings[0]?.id ?? null);
  const [findingQuery, setFindingQuery] = useState('');
  const [findingSeverityFilter, setFindingSeverityFilter] = useState<FindingSeverityFilter>('all');
  const [findingStatusFilter, setFindingStatusFilter] = useState<FindingStatusFilter>('all');
  const [findingSortKey, setFindingSortKey] = useState<FindingSortKey>('severity');
  const [reportFormat, setReportFormat] = useState<ReportFormat>('html');
  const [aiProvider, setAiProvider] = useState<AiProvider>('openai');
  const [apiKeyDraft, setApiKeyDraft] = useState('');
  const [maskedApiKey, setMaskedApiKey] = useState<string | null>(null);
  const [projectForm, setProjectForm] = useState<ProjectFormState>(emptyProjectForm);
  const [targetForm, setTargetForm] = useState<TargetFormState>(emptyTargetForm);
  const [scanForm, setScanForm] = useState<ScanFormState>(emptyScanForm);
  const [openApiDocument, setOpenApiDocument] = useState('');
  const [openApiBaseUrl, setOpenApiBaseUrl] = useState('');
  const [openApiImport, setOpenApiImport] = useState<OpenApiImportResult | null>(null);
  const [openApiError, setOpenApiError] = useState<string | null>(null);
  const [urlSeedDocument, setUrlSeedDocument] = useState('');
  const [urlSeedImport, setUrlSeedImport] = useState<UrlSeedImportResult | null>(null);
  const [urlSeedError, setUrlSeedError] = useState<string | null>(null);
  const [htmlCrawlDocument, setHtmlCrawlDocument] = useState('');
  const [htmlCrawlBaseUrl, setHtmlCrawlBaseUrl] = useState('');
  const [htmlCrawlCandidates, setHtmlCrawlCandidates] = useState<CrawlCandidate[] | null>(null);
  const [htmlCrawlError, setHtmlCrawlError] = useState<string | null>(null);
  const [browserObservationDocument, setBrowserObservationDocument] = useState('');
  const [browserObservationBaseUrl, setBrowserObservationBaseUrl] = useState('');
  const [rulePackManifest, setRulePackManifest] = useState('');
  const [rulePackExpectedSha256, setRulePackExpectedSha256] = useState('');
  const [rulePackUpdateFeed, setRulePackUpdateFeed] = useState('');
  const [rulePackFeedPublicKey, setRulePackFeedPublicKey] = useState('');
  const [rulePackBundleFile, setRulePackBundleFile] = useState<RulePackBundleFile | null>(null);
  const [rulePackBundlePublicKey, setRulePackBundlePublicKey] = useState('');
  const [rulePackFeedStatus, setRulePackFeedStatus] = useState<RulePackUpdateFeedStatus | null>(null);
  const [rulePackMessage, setRulePackMessage] = useState<string | null>(null);
  const [browserCrawlResult, setBrowserCrawlResult] = useState<BrowserCrawlResult | null>(null);
  const [browserCrawlError, setBrowserCrawlError] = useState<string | null>(null);
  const [urlCrawlResult, setUrlCrawlResult] = useState<UrlCrawlResult | null>(null);
  const [urlCrawlError, setUrlCrawlError] = useState<string | null>(null);
  const [urlCrawlMaxPages, setUrlCrawlMaxPages] = useState(10);
  const [urlCrawlMaxDepth, setUrlCrawlMaxDepth] = useState(1);
  const [engineError, setEngineError] = useState<string | null>(null);
  const [storageError, setStorageError] = useState<string | null>(null);
  const [projectFormError, setProjectFormError] = useState<string | null>(null);
  const [targetFormError, setTargetFormError] = useState<string | null>(null);
  const [scanFormError, setScanFormError] = useState<string | null>(null);
  const [findingError, setFindingError] = useState<string | null>(null);
  const [reportError, setReportError] = useState<string | null>(null);
  const [reportArtifactMessage, setReportArtifactMessage] = useState<string | null>(null);
  const [reportRetentionDays, setReportRetentionDays] = useState(30);
  const [supportDiagnosticsMessage, setSupportDiagnosticsMessage] = useState<string | null>(null);
  const [aiGuideMessage, setAiGuideMessage] = useState<string | null>(null);
  const [aiGuide, setAiGuide] = useState<AiFixGuide | null>(null);
  const [apiKeyError, setApiKeyError] = useState<string | null>(null);
  const [autoRunnerEnabled, setAutoRunnerEnabled] = useState(false);

  useEffect(() => {
    refreshEngineStatus();
    refreshStorageStatus();
    refreshUsageStatus();
    refreshWorkspaceData();
    refreshTargetEndpoints();
    refreshScans();
    refreshFindings();
    refreshAuditLogs();
    refreshRulePackStatus();
    refreshRunnerStatus();
  }, []);

  useEffect(() => {
    const pollingId = window.setInterval(() => {
      refreshScans();
      refreshFindings();
      refreshAuditLogs();
    }, 5000);
    return () => window.clearInterval(pollingId);
  }, []);

  async function refreshEngineStatus() {
    try {
      const snapshot = await invoke<EngineSnapshot>('local_engine_status');
      setEngine(snapshot);
      setEngineError(null);
    } catch {
      setEngine(previewEngine);
      setEngineError('Desktop command unavailable in browser preview');
    }
  }

  async function refreshStorageStatus() {
    try {
      const snapshot = await invoke<LocalStorageSnapshot>('local_storage_status');
      setStorage(snapshot);
      setStorageError(null);
    } catch {
      setStorage(previewStorage);
      setStorageError('Desktop storage unavailable in browser preview');
    }
  }

  async function refreshUsageStatus() {
    try {
      const snapshot = await invoke<UsageSnapshot>('local_usage_status');
      setUsage(snapshot);
    } catch {
      setUsage(previewUsage);
    }
  }

  async function refreshWorkspaceData() {
    try {
      const [projectRecords, targetRecords] = await Promise.all([
        invoke<ProjectRecord[]>('list_local_projects'),
        invoke<TargetRecord[]>('list_local_targets')
      ]);
      setProjects(projectRecords);
      setTargets(targetRecords);
      setTargetForm((current) => ({
        ...current,
        project_id: current.project_id || projectRecords[0]?.id || ''
      }));
      setScanForm((current) => ({
        ...current,
        project_id: current.project_id || projectRecords[0]?.id || '',
        target_id: current.target_id || targetRecords[0]?.id || ''
      }));
      setStorageError(null);
    } catch {
      setProjects(previewProjects);
      setTargets(previewTargets);
      setTargetForm((current) => ({
        ...current,
        project_id: current.project_id || previewProjects[0]?.id || ''
      }));
      setScanForm((current) => ({
        ...current,
        project_id: current.project_id || previewProjects[0]?.id || '',
        target_id: current.target_id || previewTargets[0]?.id || ''
      }));
      setStorageError('Desktop storage unavailable in browser preview');
    }
  }

  async function refreshTargetEndpoints() {
    try {
      const endpointRecords = await invoke<TargetEndpointRecord[]>('list_local_target_endpoints', {
        input: { target_id: null }
      });
      setTargetEndpoints(endpointRecords);
    } catch {
      setTargetEndpoints([]);
    }
  }

  async function refreshScans() {
    try {
      const scanRecords = await invoke<ScanRecord[]>('list_local_scans');
      setScans(scanRecords);
      setScanFormError(null);
    } catch {
      setScans(previewScans);
      setScanFormError('Desktop scan storage unavailable in browser preview');
    }
  }

  async function refreshFindings() {
    try {
      const findingRecords = await invoke<Finding[]>('list_local_findings');
      setFindings(findingRecords);
      setSelectedFindingId((current) => current || findingRecords[0]?.id || null);
    } catch {
      setFindings(previewFindings);
      setSelectedFindingId((current) => current || previewFindings[0]?.id || null);
    }
  }

  async function refreshAuditLogs() {
    try {
      const records = await invoke<AuditLogRecord[]>('list_local_audit_logs');
      setAuditLogs(records);
    } catch {
      setAuditLogs([]);
    }
  }

  async function refreshRulePackStatus() {
    try {
      const status = await invoke<RulePackStatus>('local_rule_pack_status');
      setRulePackStatus(status);
      setRulePackMessage(null);
    } catch {
      setRulePackStatus({
        version: '2026.06.12',
        channel: 'built-in',
        source: 'preview',
        rule_count: 0,
        enabled_rule_count: 0,
        disabled_rule_count: 0,
        published_at: null,
        imported_at: null,
        manifest_sha256: null,
        bundle_sha256: null,
        bundle_size_bytes: null,
        bundle_file_name: null,
        rollback_available: false
      });
    }
  }

  async function refreshRunnerStatus() {
    try {
      const status = await invoke<ScanRunnerStatus>('scan_runner_status');
      setAutoRunnerEnabled(status.enabled);
    } catch {
      setAutoRunnerEnabled(false);
    }
  }

  async function submitProjectForm(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    try {
      if (projectForm.id) {
        await invoke<ProjectRecord>('update_local_project', {
          input: projectForm
        });
      } else {
        await invoke<ProjectRecord>('create_local_project', {
          input: projectForm
        });
      }
      setProjectForm(emptyProjectForm);
      setProjectFormError(null);
      await refreshStorageStatus();
      await refreshUsageStatus();
      await refreshWorkspaceData();
    } catch (error) {
      setProjectFormError(toUserError(error));
    }
  }

  async function submitTargetForm(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    try {
      let savedTarget: TargetRecord;
      if (targetForm.id) {
        savedTarget = await invoke<TargetRecord>('update_local_target', {
          input: targetForm
        });
      } else {
        savedTarget = await invoke<TargetRecord>('create_local_target', {
          input: targetForm
        });
      }
      if (targetForm.target_type === 'openapi' && openApiImport?.endpoints.length) {
        await invoke<TargetEndpointRecord[]>('replace_openapi_endpoint_candidates', {
          input: {
            target_id: savedTarget.id,
            endpoints: openApiImport.endpoints
          }
        });
      }
      if (urlSeedImport?.seeds.length) {
        await invoke<TargetEndpointRecord[]>('replace_url_seed_endpoint_candidates', {
          input: {
            target_id: savedTarget.id,
            seeds: urlSeedImport.seeds
          }
        });
      }
      if (htmlCrawlCandidates?.length) {
        await invoke<TargetEndpointRecord[]>('replace_html_crawl_endpoint_candidates', {
          input: {
            target_id: savedTarget.id,
            candidates: htmlCrawlCandidates
          }
        });
      }
      if (urlCrawlResult?.candidates.length) {
        await invoke<TargetEndpointRecord[]>('replace_html_crawl_endpoint_candidates', {
          input: {
            target_id: savedTarget.id,
            candidates: urlCrawlResult.candidates
          }
        });
      }
      if (browserCrawlResult?.candidates.length) {
        await invoke<TargetEndpointRecord[]>('replace_html_crawl_endpoint_candidates', {
          input: {
            target_id: savedTarget.id,
            candidates: browserCrawlResult.candidates
          }
        });
      }
      setTargetForm({
        ...emptyTargetForm,
        project_id: targetForm.project_id || projects[0]?.id || ''
      });
      setOpenApiImport(null);
      setUrlSeedImport(null);
      setHtmlCrawlCandidates(null);
      setUrlCrawlResult(null);
      setBrowserCrawlResult(null);
      setTargetFormError(null);
      await refreshStorageStatus();
      await refreshUsageStatus();
      await refreshWorkspaceData();
      await refreshTargetEndpoints();
      await refreshAuditLogs();
    } catch (error) {
      setTargetFormError(toUserError(error));
    }
  }

  async function analyzeOpenApiDocument() {
    try {
      const result = await invoke<OpenApiImportResult>('import_openapi_document', {
        input: {
          document: openApiDocument,
          base_url: openApiBaseUrl.trim() || null
        }
      });
      setOpenApiImport(result);
      setOpenApiError(null);
      setTargetForm((current) => ({
        ...current,
        target_type: 'openapi',
        name: current.name || result.title || 'Imported OpenAPI',
        url: result.base_url
      }));
    } catch (error) {
      setOpenApiImport(null);
      setOpenApiError(toUserError(error));
    }
  }

  function loadSampleOpenApiDocument() {
    setOpenApiDocument(sampleOpenApiDocument);
    setOpenApiBaseUrl('');
    setOpenApiImport(null);
    setOpenApiError(null);
  }

  async function loadOpenApiFile(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (!file) {
      return;
    }
    try {
      setOpenApiDocument(await readTextFile(file, maxOpenApiDocumentChars));
      setOpenApiImport(null);
      setOpenApiError(null);
    } catch (error) {
      setOpenApiImport(null);
      setOpenApiError(toUserError(error));
    }
  }

  function applyOpenApiTarget() {
    if (!openApiImport) {
      return;
    }
    setTargetForm((current) => ({
      ...current,
      target_type: 'openapi',
      name: current.name || openApiImport.title || 'Imported OpenAPI',
      url: openApiImport.base_url
    }));
    setTargetFormError(null);
  }

  async function analyzeUrlSeedDocument() {
    try {
      const result = await invoke<UrlSeedImportResult>('import_url_seed_document', {
        input: {
          document: urlSeedDocument
        }
      });
      setUrlSeedImport(result);
      setUrlSeedError(null);
      setTargetForm((current) => ({
        ...current,
        target_type: 'url',
        name: current.name || 'Imported URL Seeds',
        url: result.seeds[0]?.url || current.url
      }));
    } catch (error) {
      setUrlSeedImport(null);
      setUrlSeedError(toUserError(error));
    }
  }

  function loadSampleUrlSeedDocument() {
    setUrlSeedDocument(sampleUrlSeedDocument);
    setUrlSeedImport(null);
    setUrlSeedError(null);
  }

  async function loadUrlSeedFile(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (!file) {
      return;
    }
    try {
      setUrlSeedDocument(await readTextFile(file, maxUrlSeedDocumentChars));
      setUrlSeedImport(null);
      setUrlSeedError(null);
    } catch (error) {
      setUrlSeedImport(null);
      setUrlSeedError(toUserError(error));
    }
  }

  function applyUrlSeedTarget() {
    if (!urlSeedImport) {
      return;
    }
    setTargetForm((current) => ({
      ...current,
      target_type: 'url',
      name: current.name || 'Imported URL Seeds',
      url: urlSeedImport.seeds[0]?.url || current.url
    }));
    setTargetFormError(null);
  }

  async function analyzeHtmlCrawlDocument() {
    try {
      const candidates = await invoke<CrawlCandidate[]>('crawl_html_document', {
        input: {
          document: htmlCrawlDocument,
          base_url: htmlCrawlBaseUrl.trim()
        }
      });
      setHtmlCrawlCandidates(candidates);
      setHtmlCrawlError(null);
      setTargetForm((current) => ({
        ...current,
        target_type: 'url',
        name: current.name || 'Imported HTML Crawl',
        url: htmlCrawlBaseUrl.trim() || current.url
      }));
    } catch (error) {
      setHtmlCrawlCandidates(null);
      setHtmlCrawlError(toUserError(error));
    }
  }

  function loadSampleHtmlCrawlDocument() {
    setHtmlCrawlDocument(sampleHtmlDocument);
    setHtmlCrawlBaseUrl('https://example.com/');
    setHtmlCrawlCandidates(null);
    setHtmlCrawlError(null);
  }

  async function loadHtmlCrawlFile(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (!file) {
      return;
    }
    try {
      setHtmlCrawlDocument(await readTextFile(file, maxHtmlDocumentChars));
      setHtmlCrawlCandidates(null);
      setHtmlCrawlError(null);
    } catch (error) {
      setHtmlCrawlCandidates(null);
      setHtmlCrawlError(toUserError(error));
    }
  }

  function applyHtmlCrawlTarget() {
    if (!htmlCrawlCandidates) {
      return;
    }
    setTargetForm((current) => ({
      ...current,
      target_type: 'url',
      name: current.name || 'Imported HTML Crawl',
      url: htmlCrawlBaseUrl.trim() || current.url
    }));
    setTargetFormError(null);
  }

  async function analyzeBrowserObservationDocument() {
    try {
      const candidates = await invoke<CrawlCandidate[]>('crawl_browser_observation', {
        input: {
          document: browserObservationDocument,
          base_url: browserObservationBaseUrl.trim()
        }
      });
      setBrowserCrawlResult({
        base_url: browserObservationBaseUrl.trim(),
        candidate_count: candidates.length,
        candidates
      });
      setBrowserCrawlError(null);
      setTargetForm((current) => ({
        ...current,
        target_type: 'url',
        name: current.name || 'Browser Crawl Surface',
        url: browserObservationBaseUrl.trim() || current.url
      }));
    } catch (error) {
      setBrowserCrawlResult(null);
      setBrowserCrawlError(toUserError(error));
    }
  }

  function loadSampleBrowserObservationDocument() {
    setBrowserObservationDocument(sampleBrowserObservationDocument);
    setBrowserObservationBaseUrl('https://example.com/app');
    setBrowserCrawlResult(null);
    setBrowserCrawlError(null);
  }

  async function loadBrowserObservationFile(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (!file) {
      return;
    }
    try {
      setBrowserObservationDocument(await readTextFile(file, maxBrowserObservationDocumentChars));
      setBrowserCrawlResult(null);
      setBrowserCrawlError(null);
    } catch (error) {
      setBrowserCrawlResult(null);
      setBrowserCrawlError(toUserError(error));
    }
  }

  async function loadRulePackBundleFile(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (!file) {
      return;
    }
    try {
      const bytes = await readBinaryFile(file, maxRulePackBundleBytes);
      setRulePackBundleFile({
        name: file.name,
        size: file.size,
        bytes
      });
      setRulePackMessage(`Loaded ${file.name} (${formatBytes(file.size)}).`);
    } catch (error) {
      setRulePackBundleFile(null);
      setRulePackMessage(toUserError(error));
    }
  }

  function loadSampleRulePackManifest() {
    setRulePackManifest(sampleRulePackManifest);
    setRulePackMessage(null);
  }

  function loadSampleRulePackUpdateFeed() {
    setRulePackUpdateFeed(sampleRulePackUpdateFeed);
    setRulePackFeedStatus(null);
    setRulePackMessage(null);
  }

  async function importRulePackManifest() {
    try {
      const status = await invoke<RulePackStatus>('import_rule_pack_manifest', {
        input: {
          document: rulePackManifest,
          expected_manifest_sha256: rulePackExpectedSha256.trim() || null
        }
      });
      setRulePackStatus(status);
      setRulePackMessage(
        `Imported rule pack ${status.version} with ${status.rule_count} rules. SHA-256 ${status.manifest_sha256?.slice(0, 16)}...`
      );
      await refreshAuditLogs();
    } catch (error) {
      setRulePackMessage(toUserError(error));
    }
  }

  async function importRulePackBundle() {
    if (!rulePackBundleFile) {
      setRulePackMessage('Choose a rule pack ZIP bundle before importing.');
      return;
    }
    try {
      const status = await invoke<RulePackStatus>('import_rule_pack_bundle', {
        input: {
          bundle_bytes: rulePackBundleFile.bytes,
          bundle_file_name: rulePackBundleFile.name,
          expected_manifest_sha256: rulePackExpectedSha256.trim() || null,
          public_key_hex: rulePackBundlePublicKey.trim() || null
        }
      });
      setRulePackStatus(status);
      setRulePackMessage(
        `Imported signed bundle ${status.version} with ${status.rule_count} rules. SHA-256 ${status.manifest_sha256?.slice(0, 16)}...`
      );
      await refreshAuditLogs();
    } catch (error) {
      setRulePackMessage(toUserError(error));
    }
  }

  async function checkRulePackUpdateFeed() {
    try {
      const status = await invoke<RulePackUpdateFeedStatus>('check_rule_pack_update_feed', {
        input: {
          document: rulePackUpdateFeed,
          public_key_hex: rulePackFeedPublicKey.trim() || null
        }
      });
      setRulePackFeedStatus(status);
      setRulePackMessage(
        status.update_available
          ? `Feed has ${status.latest_version} for ${status.channel}.`
          : `Feed matches current rule pack ${status.current_version}.`
      );
      await refreshAuditLogs();
    } catch (error) {
      setRulePackMessage(toUserError(error));
    }
  }

  async function rollbackRulePackManifest() {
    try {
      const status = await invoke<RulePackStatus>('rollback_rule_pack_manifest', {
        input: { confirm: true }
      });
      setRulePackStatus(status);
      setRulePackMessage(`Rolled back to rule pack ${status.version}.`);
      await refreshAuditLogs();
    } catch (error) {
      setRulePackMessage(toUserError(error));
    }
  }

  function applyBrowserCrawlTarget() {
    if (!browserCrawlResult) {
      return;
    }
    setTargetForm((current) => ({
      ...current,
      target_type: 'url',
      name: current.name || 'Browser Crawl Surface',
      url: browserCrawlResult.base_url || current.url
    }));
    setTargetFormError(null);
  }

  async function runApprovedUrlCrawl() {
    try {
      const result = await invoke<UrlCrawlResult>('crawl_approved_url', {
        input: {
          url: targetForm.url.trim(),
          approval_note: targetForm.approval_note.trim(),
          allow_private_network: targetForm.allow_private_network,
          max_pages: urlCrawlMaxPages,
          max_candidates: 250,
          max_depth: urlCrawlMaxDepth
        }
      });
      setUrlCrawlResult(result);
      setUrlCrawlError(null);
      setTargetForm((current) => ({
        ...current,
        target_type: 'url',
        name: current.name || 'Live URL Crawl',
        url: result.seed_url || current.url
      }));
    } catch (error) {
      setUrlCrawlResult(null);
      setUrlCrawlError(toUserError(error));
    }
  }

  function applyUrlCrawlTarget() {
    if (!urlCrawlResult) {
      return;
    }
    setTargetForm((current) => ({
      ...current,
      target_type: 'url',
      name: current.name || 'Live URL Crawl',
      url: urlCrawlResult.seed_url || current.url
    }));
    setTargetFormError(null);
  }

  async function submitScanForm(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    try {
      await invoke<ScanRecord>('create_local_scan', {
        input: scanForm
      });
      setScanFormError(null);
      await refreshStorageStatus();
      await refreshUsageStatus();
      await refreshScans();
    } catch (error) {
      setScanFormError(toUserError(error));
    }
  }

  async function advanceScanQueue() {
    try {
      await invoke<ScanRecord | null>('advance_local_scan');
      setScanFormError(null);
      await refreshScans();
      await refreshFindings();
      await refreshUsageStatus();
    } catch (error) {
      setScanFormError(toUserError(error));
    }
  }

  async function runScanQueue() {
    try {
      await invoke<ScanRecord[]>('run_local_scan_queue');
      setScanFormError(null);
      await refreshScans();
      await refreshFindings();
      await refreshUsageStatus();
    } catch (error) {
      setAutoRunnerEnabled(false);
      setScanFormError(toUserError(error));
    }
  }

  async function toggleBackgroundRunner() {
    try {
      const status = await invoke<ScanRunnerStatus>('set_scan_runner_enabled', {
        input: { enabled: !autoRunnerEnabled }
      });
      setAutoRunnerEnabled(status.enabled);
      setScanFormError(null);
    } catch (error) {
      setAutoRunnerEnabled(false);
      setScanFormError(toUserError(error));
    }
  }

  async function cancelScan(scan: ScanRecord) {
    try {
      await invoke<ScanRecord>('cancel_local_scan', { input: { scan_id: scan.id } });
      setScanFormError(null);
      await refreshScans();
      await refreshFindings();
      await refreshUsageStatus();
      await refreshRunnerStatus();
    } catch (error) {
      setScanFormError(toUserError(error));
    }
  }

  async function compareScanBaseline(scan: ScanRecord) {
    try {
      const diff = await invoke<BaselineDiffSummary>('local_scan_baseline_diff', {
        input: { scan_id: scan.id }
      });
      setBaselineDiffs((current) => ({
        ...current,
        [scan.id]: diff
      }));
      setScanFormError(null);
    } catch (error) {
      setScanFormError(toUserError(error));
    }
  }

  async function changeFindingStatus(finding: Finding, status: FindingStatus) {
    try {
      await invoke<Finding>('update_local_finding_status', {
        input: { id: finding.id, status }
      });
      setFindingError(null);
      await refreshFindings();
      await refreshAuditLogs();
    } catch (error) {
      setFindingError(toUserError(error));
    }
  }

  async function archiveProject(project: ProjectRecord) {
    try {
      await invoke('deactivate_local_project', { input: { project_id: project.id } });
      await refreshStorageStatus();
      await refreshUsageStatus();
      await refreshWorkspaceData();
    } catch {
      setStorageError('Unable to archive project in browser preview');
    }
  }

  async function renameTarget(target: TargetRecord) {
    setTargetForm({
      id: target.id,
      project_id: target.project_id,
      target_type: target.target_type as TargetFormState['target_type'],
      name: target.name,
      url: target.url,
      approval_note: target.approval_note,
      allow_private_network: target.allow_private_network
    });
    setTargetFormError(null);
  }

  async function archiveTarget(target: TargetRecord) {
    try {
      await invoke('deactivate_local_target', { input: { target_id: target.id } });
      await refreshStorageStatus();
      await refreshUsageStatus();
      await refreshWorkspaceData();
    } catch {
      setStorageError('Unable to archive target in browser preview');
    }
  }

  async function runEngineCommand(command: 'start_local_engine' | 'stop_local_engine') {
    try {
      const snapshot = await invoke<EngineSnapshot>(command);
      setEngine(snapshot);
      setEngineError(null);
    } catch {
      setEngine(previewEngine);
      setEngineError('Desktop command unavailable in browser preview');
    }
  }

  async function exportFindingReport() {
    const visibleFindings = filterAndSortFindings(
      findings,
      findingQuery,
      findingSeverityFilter,
      findingStatusFilter,
      findingSortKey
    );
    if (reportFormat === 'pdf') {
      const reportInput = {
        findings: visibleFindings,
        query: findingQuery,
        severityFilter: findingSeverityFilter,
        statusFilter: findingStatusFilter,
        sortKey: findingSortKey,
        generatedAt: new Date()
      };
      try {
        const pdfReport = buildPdfReport(reportInput);
        const artifact = buildReportArtifactMetadata('pdf');
        await recordReportExport(reportFormat, visibleFindings.length, artifact, pdfReport);
        downloadReport(pdfReport, artifact.fileName, 'application/pdf');
      } catch (error) {
        setReportError(toUserError(error));
        return;
      }
      setReportError(null);
      return;
    }
    if (reportFormat === 'sarif') {
      try {
        const sarifReport = JSON.stringify(buildSarifReport(visibleFindings), null, 2);
        const artifact = buildReportArtifactMetadata('sarif');
        await recordReportExport(reportFormat, visibleFindings.length, artifact, sarifReport);
        downloadReport(sarifReport, artifact.fileName, 'application/sarif+json;charset=utf-8');
      } catch (error) {
        setReportError(toUserError(error));
        return;
      }
      setReportError(null);
      return;
    }
    const reportInput = {
      findings: visibleFindings,
      query: findingQuery,
      severityFilter: findingSeverityFilter,
      statusFilter: findingStatusFilter,
      sortKey: findingSortKey,
      generatedAt: new Date()
    };
    const report =
      reportFormat === 'json'
        ? JSON.stringify(buildJsonReport(reportInput), null, 2)
        : reportFormat === 'html'
          ? buildHtmlReport(reportInput)
          : buildMarkdownReport(reportInput);
    const extension = reportFormat === 'json' ? 'json' : reportFormat === 'html' ? 'html' : 'md';
    const mime =
      reportFormat === 'json'
        ? 'application/json;charset=utf-8'
        : reportFormat === 'html'
          ? 'text/html;charset=utf-8'
          : 'text/markdown;charset=utf-8';
    try {
      const artifact = buildReportArtifactMetadata(extension);
      await recordReportExport(reportFormat, visibleFindings.length, artifact, report);
      downloadReport(report, artifact.fileName, mime);
    } catch (error) {
      setReportError(toUserError(error));
      return;
    }
    setReportError(null);
  }

  async function recordReportExport(
    format: ReportFormat,
    findingCount: number,
    artifact: ReportArtifactMetadata,
    content: string
  ) {
    const result = await invoke<ReportExportResult>('record_report_export', {
      input: {
        format,
        finding_count: findingCount,
        artifact_file_name: artifact.fileName,
        artifact_content: content
      }
    });
    setUsage(result.usage);
    await refreshAuditLogs();
  }

  function downloadReport(content: string, fileName: string, mime: string) {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = fileName;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  async function cleanupOldReportArtifacts() {
    const retentionDays = Math.trunc(reportRetentionDays);
    if (!Number.isFinite(retentionDays) || retentionDays < 1 || retentionDays > 3650) {
      setReportArtifactMessage('Retention must be between 1 and 3650 days.');
      return;
    }
    try {
      const result = await invoke<CleanupReportArtifactsResult>('cleanup_report_artifacts', {
        input: { older_than_days: retentionDays }
      });
      setReportArtifactMessage(
        `Deleted ${result.deleted_count} report artifacts older than ${retentionDays}d (${formatBytes(result.deleted_bytes)}).`
      );
      await refreshAuditLogs();
    } catch (error) {
      setReportArtifactMessage(toUserError(error));
    }
  }

  async function collectSupportDiagnostics() {
    try {
      const result = await invoke<SupportDiagnosticsResult>('collect_support_diagnostics');
      setSupportDiagnosticsMessage(
        `${result.relative_path} · ${formatBytes(result.size_bytes)} · ${result.sha256.slice(0, 16)}`
      );
      await refreshAuditLogs();
    } catch (error) {
      setSupportDiagnosticsMessage(toUserError(error));
    }
  }

  async function prepareAiFixGuide() {
    if (!selectedFinding) {
      setAiGuideMessage('Select a finding before preparing an AI Fix Guide.');
      return;
    }
    if (!maskedApiKey) {
      setAiGuideMessage('Save a user API key before generating an AI Fix Guide.');
      return;
    }
    try {
      const request = buildAiFixGuideInput(selectedFinding);
      const guide = await invoke<AiFixGuide>('generate_ai_fix_guide', {
        input: {
          provider: aiProvider,
          account: 'local-user',
          request: {
            ...request,
            evidence: JSON.stringify(request.evidence)
          }
        }
      });
      setAiGuide(guide);
      setAiGuideMessage('AI Fix Guide draft generated for the selected finding.');
      await refreshAuditLogs();
    } catch (error) {
      setAiGuideMessage(toUserError(error));
    }
  }

  async function saveApiKeySession() {
    const trimmed = apiKeyDraft.trim();
    if (trimmed.length < 20) {
      setApiKeyError('API key is too short to save for this session.');
      return;
    }
    try {
      const snapshot = await invoke<SecretSnapshot>('save_ai_api_key', {
        input: {
          provider: aiProvider,
          account: 'local-user',
          secret_value: trimmed
        }
      });
      setMaskedApiKey(snapshot.masked_value);
      setApiKeyDraft('');
      setApiKeyError(null);
    } catch {
      setMaskedApiKey(maskSecret(trimmed));
      setApiKeyDraft('');
      setApiKeyError('Desktop secure store unavailable; key is session-only in preview.');
    }
  }

  async function clearApiKeySession() {
    try {
      await invoke('delete_ai_api_key', {
        input: {
          provider: aiProvider,
          account: 'local-user'
        }
      });
    } catch {
      // Browser preview has no Tauri command; local UI state is still cleared.
    } finally {
      setMaskedApiKey(null);
      setApiKeyDraft('');
      setApiKeyError(null);
    }
  }

  const engineLabel = engine.status.replace('_', ' ');
  const scanTargets = targets.filter((target) => !scanForm.project_id || target.project_id === scanForm.project_id);
  const latestScan = scans[0];
  const endpointCountByTarget = targetEndpoints.reduce<Record<string, number>>((counts, endpoint) => {
    counts[endpoint.target_id] = (counts[endpoint.target_id] || 0) + 1;
    return counts;
  }, {});
  const visibleFindings = filterAndSortFindings(
    findings,
    findingQuery,
    findingSeverityFilter,
    findingStatusFilter,
    findingSortKey
  );
  const selectedFinding = visibleFindings.find((finding) => finding.id === selectedFindingId) ?? visibleFindings[0] ?? null;
  const findingSummary = summarizeFindings(visibleFindings);
  const aiFixGuideInput = selectedFinding ? buildAiFixGuideInput(selectedFinding) : null;
  const reportHistory = auditLogs.filter((log) => log.action === 'report.generated');

  return (
    <div className="app-shell">
      <header className="title-bar">
        <div>
          <strong>Aegis WebShield AI</strong>
          <span className="title-muted">Windows Desktop</span>
        </div>
        <div className="title-actions">
          <span className="usage-pill">
            Community · {usage.monthly_scans} scans this month
          </span>
          <span className={`engine-pill ${engine.status}`}>Local Engine {engineLabel}</span>
        </div>
      </header>

      <aside className="sidebar">
        <div className="workspace">
          <div className="workspace-mark">A</div>
          <div>
            <strong>Local Workspace</strong>
            <span>Approved targets only</span>
          </div>
        </div>
        <nav>
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <button className={`nav-item ${item.active ? 'active' : ''}`} key={item.label} type="button">
                <Icon size={18} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
      </aside>

      <main className="content">
        <section className="page-header">
          <div>
            <span className="eyebrow">Open-source desktop security scanner</span>
            <h1>Security Dashboard</h1>
          </div>
          <div className="header-actions">
            <button className="secondary-button" type="button" onClick={exportFindingReport}>
              <Download size={16} />
              Export report
            </button>
            <button className="primary-button" type="button">
              <Play size={16} />
              New scan
            </button>
          </div>
        </section>

        <section className="metrics-grid" aria-label="Security summary">
          <Metric label="Projects" value={`${projects.length}`} subtext="local workspace" />
          <Metric label="Approved Targets" value={`${targets.length}`} subtext="private CIDR blocked" />
          <Metric label="Queued Scans" value={`${scans.length}`} subtext="local scan jobs" />
          <Metric label="Local DB" value={`${storage.workspace_count}`} subtext={`${storage.applied_migrations.length} migration applied`} />
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <h2>Projects & Approved Targets</h2>
              <p>Local SQLite records used by scan setup and scope validation.</p>
            </div>
            <div className="engine-actions">
              <button className="secondary-button" type="button" onClick={refreshWorkspaceData}>
                Refresh
              </button>
            </div>
          </div>
          <div className="forms-grid">
            <form className="record-form" onSubmit={submitProjectForm}>
              <div className="form-title">
                <strong>{projectForm.id ? 'Edit project' : 'New project'}</strong>
                {projectForm.id ? (
                  <button type="button" onClick={() => setProjectForm(emptyProjectForm)}>
                    <X size={14} />
                  </button>
                ) : null}
              </div>
              <label>
                <span>Name</span>
                <input
                  maxLength={120}
                  onChange={(event) => setProjectForm({ ...projectForm, name: event.target.value })}
                  placeholder="Production web"
                  required
                  value={projectForm.name}
                />
              </label>
              <label>
                <span>Description</span>
                <input
                  maxLength={500}
                  onChange={(event) => setProjectForm({ ...projectForm, description: event.target.value })}
                  placeholder="External customer-facing surface"
                  value={projectForm.description}
                />
              </label>
              {projectFormError ? <p className="inline-warning">{projectFormError}</p> : null}
              <button className="primary-button" type="submit">
                <Check size={16} />
                {projectForm.id ? 'Save project' : 'Create project'}
              </button>
            </form>

            <form className="record-form" onSubmit={submitTargetForm}>
              <div className="form-title">
                <strong>{targetForm.id ? 'Edit target' : 'New approved target'}</strong>
                {targetForm.id ? (
                  <button type="button" onClick={() => setTargetForm({ ...emptyTargetForm, project_id: projects[0]?.id || '' })}>
                    <X size={14} />
                  </button>
                ) : null}
              </div>
              <label>
                <span>Project</span>
                <select
                  onChange={(event) => setTargetForm({ ...targetForm, project_id: event.target.value })}
                  required
                  value={targetForm.project_id}
                >
                  <option value="" disabled>Select project</option>
                  {projects.map((project) => (
                    <option key={project.id} value={project.id}>{project.name}</option>
                  ))}
                </select>
              </label>
              <label>
                <span>Type</span>
                <select
                  onChange={(event) => setTargetForm({ ...targetForm, target_type: event.target.value as TargetFormState['target_type'] })}
                  value={targetForm.target_type}
                >
                  <option value="url">URL</option>
                  <option value="api">API</option>
                  <option value="openapi">OpenAPI</option>
                </select>
              </label>
              <label>
                <span>Name</span>
                <input
                  maxLength={120}
                  onChange={(event) => setTargetForm({ ...targetForm, name: event.target.value })}
                  placeholder="Public app"
                  required
                  value={targetForm.name}
                />
              </label>
              <label>
                <span>URL</span>
                <input
                  maxLength={2048}
                  onChange={(event) => setTargetForm({ ...targetForm, url: event.target.value })}
                  placeholder="https://app.example.com"
                  required
                  type="url"
                  value={targetForm.url}
                />
              </label>
              <label>
                <span>Approval note</span>
                <input
                  maxLength={1000}
                  onChange={(event) => setTargetForm({ ...targetForm, approval_note: event.target.value })}
                  placeholder="Ticket or written owner approval"
                  required
                  value={targetForm.approval_note}
                />
              </label>
              <label className="checkbox-row">
                <input
                  checked={targetForm.allow_private_network}
                  onChange={(event) => setTargetForm({ ...targetForm, allow_private_network: event.target.checked })}
                  type="checkbox"
                />
                <span>Allow private network target</span>
              </label>
              {targetFormError ? <p className="inline-warning">{targetFormError}</p> : null}
              <button className="primary-button" disabled={!projects.length} type="submit">
                <Check size={16} />
                {targetForm.id ? 'Save target' : 'Create target'}
              </button>
            </form>
          </div>
          <div className="openapi-importer">
            <div className="form-title">
              <strong>OpenAPI import</strong>
              <div className="form-title-actions">
                <label aria-label="Load OpenAPI file" className="file-action" title="Load OpenAPI file">
                  <Upload size={14} />
                  <input accept=".json,.yaml,.yml,application/json,text/yaml,text/x-yaml" type="file" onChange={loadOpenApiFile} />
                </label>
                <button type="button" onClick={loadSampleOpenApiDocument}>
                  <FileText size={14} />
                </button>
              </div>
            </div>
            <div className="openapi-import-grid">
              <label>
                <span>Document</span>
                <textarea
                  maxLength={maxOpenApiDocumentChars}
                  onChange={(event) => setOpenApiDocument(event.target.value)}
                  placeholder="Paste OpenAPI 3.x JSON or YAML"
                  value={openApiDocument}
                />
              </label>
              <div className="openapi-side">
                <label>
                  <span>Base URL override</span>
                  <input
                    maxLength={2048}
                    onChange={(event) => setOpenApiBaseUrl(event.target.value)}
                    placeholder="https://api.example.com"
                    type="url"
                    value={openApiBaseUrl}
                  />
                </label>
                <div className="engine-actions">
                  <button className="secondary-button" disabled={!openApiDocument.trim()} type="button" onClick={analyzeOpenApiDocument}>
                    <Radar size={16} />
                    Analyze
                  </button>
                  <button className="primary-button" disabled={!openApiImport} type="button" onClick={applyOpenApiTarget}>
                    <Check size={16} />
                    Use as target
                  </button>
                </div>
                {openApiError ? <p className="inline-warning">{openApiError}</p> : null}
                {openApiImport ? (
                  <div className="openapi-summary">
                    <strong>{openApiImport.title || 'OpenAPI document'}</strong>
                    <span>{openApiImport.version || 'no version'} · {openApiImport.endpoints.length} endpoints</span>
                    <code>{openApiImport.base_url}</code>
                    <div className="endpoint-list">
                      {openApiImport.endpoints.slice(0, 6).map((endpoint) => (
                        <div className="endpoint-row" key={`${endpoint.method}-${endpoint.path}`}>
                          <strong>{endpoint.method}</strong>
                          <span>
                            {endpoint.path}
                            {endpoint.tags.length || endpoint.security_requirements.length ? (
                              <small>
                                {[...endpoint.tags, ...endpoint.security_requirements.map((name) => `security:${name}`)].join(' / ')}
                              </small>
                            ) : null}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : null}
              </div>
            </div>
          </div>
          <div className="openapi-importer">
            <div className="form-title">
              <strong>URL seed import</strong>
              <div className="form-title-actions">
                <label aria-label="Load URL seed file" className="file-action" title="Load URL seed file">
                  <Upload size={14} />
                  <input accept=".txt,.csv,.list,text/plain,text/csv" type="file" onChange={loadUrlSeedFile} />
                </label>
                <button type="button" onClick={loadSampleUrlSeedDocument}>
                  <FileText size={14} />
                </button>
              </div>
            </div>
            <div className="openapi-import-grid">
              <label>
                <span>URL list</span>
                <textarea
                  maxLength={maxUrlSeedDocumentChars}
                  onChange={(event) => setUrlSeedDocument(event.target.value)}
                  placeholder="One approved HTTP/HTTPS URL per line"
                  value={urlSeedDocument}
                />
              </label>
              <div className="openapi-side">
                <div className="engine-actions">
                  <button className="secondary-button" disabled={!urlSeedDocument.trim()} type="button" onClick={analyzeUrlSeedDocument}>
                    <Radar size={16} />
                    Analyze
                  </button>
                  <button className="primary-button" disabled={!urlSeedImport} type="button" onClick={applyUrlSeedTarget}>
                    <Check size={16} />
                    Use as target
                  </button>
                </div>
                {urlSeedError ? <p className="inline-warning">{urlSeedError}</p> : null}
                {urlSeedImport ? (
                  <div className="openapi-summary">
                    <strong>URL seed list</strong>
                    <span>{urlSeedImport.seed_count} seeds 쨌 {urlSeedImport.skipped_count} skipped</span>
                    <code>{urlSeedImport.seeds[0]?.url || 'no seed URL'}</code>
                    <div className="endpoint-list">
                      {urlSeedImport.seeds.slice(0, 6).map((seed) => (
                        <div className="endpoint-row" key={seed.url}>
                          <strong>GET</strong>
                          <span>{seed.url}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : null}
              </div>
            </div>
          </div>
          <div className="openapi-importer">
            <div className="form-title">
              <strong>HTML crawler</strong>
              <div className="form-title-actions">
                <label aria-label="Load HTML file" className="file-action" title="Load HTML file">
                  <Upload size={14} />
                  <input accept=".html,.htm,text/html" type="file" onChange={loadHtmlCrawlFile} />
                </label>
                <button type="button" onClick={loadSampleHtmlCrawlDocument}>
                  <FileText size={14} />
                </button>
              </div>
            </div>
            <div className="openapi-import-grid">
              <label>
                <span>HTML document</span>
                <textarea
                  maxLength={maxHtmlDocumentChars}
                  onChange={(event) => setHtmlCrawlDocument(event.target.value)}
                  placeholder="Paste approved page HTML"
                  value={htmlCrawlDocument}
                />
              </label>
              <div className="openapi-side">
                <label>
                  <span>Base URL</span>
                  <input
                    maxLength={2048}
                    onChange={(event) => setHtmlCrawlBaseUrl(event.target.value)}
                    placeholder="https://example.com/app"
                    type="url"
                    value={htmlCrawlBaseUrl}
                  />
                </label>
                <div className="engine-actions">
                  <button
                    className="secondary-button"
                    disabled={!htmlCrawlDocument.trim() || !htmlCrawlBaseUrl.trim()}
                    type="button"
                    onClick={analyzeHtmlCrawlDocument}
                  >
                    <Radar size={16} />
                    Analyze
                  </button>
                  <button className="primary-button" disabled={!htmlCrawlCandidates} type="button" onClick={applyHtmlCrawlTarget}>
                    <Check size={16} />
                    Use as target
                  </button>
                </div>
                {htmlCrawlError ? <p className="inline-warning">{htmlCrawlError}</p> : null}
                {htmlCrawlCandidates ? (
                  <div className="openapi-summary">
                    <strong>HTML crawl candidates</strong>
                    <span>{htmlCrawlCandidates.length} same-origin candidates</span>
                    <code>{htmlCrawlBaseUrl || 'no base URL'}</code>
                    <div className="endpoint-list">
                      {htmlCrawlCandidates.slice(0, 6).map((candidate) => (
                        <div className="endpoint-row" key={`${candidate.method}-${candidate.url}`}>
                          <strong>{candidate.method}</strong>
                          <span>{candidate.url}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : null}
              </div>
            </div>
          </div>
          <div className="openapi-importer">
            <div className="form-title">
              <strong>Live URL crawler</strong>
            </div>
            <div className="openapi-import-grid">
              <div className="openapi-summary">
                <strong>{targetForm.url.trim() || 'No target URL'}</strong>
                <span>{targetForm.approval_note.trim() ? 'Approval note ready' : 'Approval note required'}</span>
                <code>{targetForm.allow_private_network ? 'private network allowed' : 'public targets only'}</code>
              </div>
              <div className="openapi-side">
                <div className="inline-fields">
                  <label>
                    <span>Max pages</span>
                    <input
                      max={50}
                      min={1}
                      onChange={(event) => setUrlCrawlMaxPages(Number(event.target.value))}
                      type="number"
                      value={urlCrawlMaxPages}
                    />
                  </label>
                  <label>
                    <span>Max depth</span>
                    <input
                      max={3}
                      min={0}
                      onChange={(event) => setUrlCrawlMaxDepth(Number(event.target.value))}
                      type="number"
                      value={urlCrawlMaxDepth}
                    />
                  </label>
                </div>
                <div className="engine-actions">
                  <button
                    className="secondary-button"
                    disabled={!targetForm.url.trim() || !targetForm.approval_note.trim()}
                    type="button"
                    onClick={runApprovedUrlCrawl}
                  >
                    <Radar size={16} />
                    Crawl
                  </button>
                  <button className="primary-button" disabled={!urlCrawlResult} type="button" onClick={applyUrlCrawlTarget}>
                    <Check size={16} />
                    Use as target
                  </button>
                </div>
                {urlCrawlError ? <p className="inline-warning">{urlCrawlError}</p> : null}
                {urlCrawlResult ? (
                  <div className="openapi-summary">
                    <strong>Live crawl result</strong>
                    <span>{urlCrawlResult.page_count} pages / {urlCrawlResult.candidate_count} candidates</span>
                    <code>{urlCrawlResult.seed_url}</code>
                    <div className="endpoint-list">
                      {urlCrawlResult.candidates.slice(0, 6).map((candidate) => (
                        <div className="endpoint-row" key={`${candidate.method}-${candidate.url}`}>
                          <strong>{candidate.method}</strong>
                          <span>{candidate.url}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : null}
              </div>
            </div>
          </div>
          <div className="openapi-importer">
            <div className="form-title">
              <strong>Browser observation</strong>
              <div className="form-title-actions">
                <label aria-label="Load browser observation file" className="file-action" title="Load browser observation file">
                  <Upload size={14} />
                  <input accept=".json,application/json" type="file" onChange={loadBrowserObservationFile} />
                </label>
                <button type="button" onClick={loadSampleBrowserObservationDocument}>
                  <FileText size={14} />
                </button>
              </div>
            </div>
            <div className="openapi-import-grid">
              <label>
                <span>Observation JSON</span>
                <textarea
                  maxLength={maxBrowserObservationDocumentChars}
                  onChange={(event) => setBrowserObservationDocument(event.target.value)}
                  placeholder="Paste browser crawl worker JSON"
                  value={browserObservationDocument}
                />
              </label>
              <div className="openapi-side">
                <label>
                  <span>Base URL</span>
                  <input
                    maxLength={2048}
                    onChange={(event) => setBrowserObservationBaseUrl(event.target.value)}
                    placeholder="https://example.com/app"
                    type="url"
                    value={browserObservationBaseUrl}
                  />
                </label>
                <div className="engine-actions">
                  <button
                    className="secondary-button"
                    disabled={!browserObservationDocument.trim() || !browserObservationBaseUrl.trim()}
                    type="button"
                    onClick={analyzeBrowserObservationDocument}
                  >
                    <Radar size={16} />
                    Analyze
                  </button>
                  <button className="primary-button" disabled={!browserCrawlResult} type="button" onClick={applyBrowserCrawlTarget}>
                    <Check size={16} />
                    Use as target
                  </button>
                </div>
                {browserCrawlError ? <p className="inline-warning">{browserCrawlError}</p> : null}
                {browserCrawlResult ? (
                  <div className="openapi-summary">
                    <strong>Browser surface candidates</strong>
                    <span>{browserCrawlResult.candidate_count} route/XHR/fetch candidates</span>
                    <code>{browserCrawlResult.base_url || 'no base URL'}</code>
                    <div className="endpoint-list">
                      {browserCrawlResult.candidates.slice(0, 6).map((candidate) => (
                        <div className="endpoint-row" key={`${candidate.method}-${candidate.url}`}>
                          <strong>{candidate.method}</strong>
                          <span>{candidate.url}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : null}
              </div>
            </div>
          </div>
          <div className="workspace-grid">
            <div className="record-list">
              <strong>Projects</strong>
              {projects.map((project) => (
                <div className="record-row" key={project.id}>
                  <span>{project.name}</span>
                  <small>{project.target_count} targets</small>
                  <button type="button" onClick={() => {
                    setProjectForm({
                      id: project.id,
                      name: project.name,
                      description: project.description
                    });
                    setProjectFormError(null);
                  }}>
                    <Edit3 size={13} />
                  </button>
                  <button type="button" onClick={() => archiveProject(project)}>Archive</button>
                </div>
              ))}
            </div>
            <div className="record-list">
              <strong>Approved targets</strong>
              {targets.map((target) => (
                <div className="record-row" key={target.id}>
                  <span>{target.name}</span>
                  <code>{target.url}</code>
                  <small>{endpointCountByTarget[target.id] || 0} endpoints</small>
                  <button type="button" onClick={() => renameTarget(target)}>
                    <Edit3 size={13} />
                  </button>
                  <button type="button" onClick={() => archiveTarget(target)}>Archive</button>
                </div>
              ))}
            </div>
          </div>
          {storageError ? <p className="inline-warning">{storageError}</p> : null}
        </section>

        <section className="work-grid">
          <div className="panel">
            <div className="panel-header">
              <div>
              <h2>Scan setup</h2>
              <p>Creates a local scan job for an approved active target.</p>
            </div>
              <div className="engine-actions">
                <button className="secondary-button" type="button" onClick={advanceScanQueue}>
                  Advance scan
                </button>
                <button className="secondary-button" type="button" onClick={runScanQueue}>
                  Run queue
                </button>
                <button
                  className={autoRunnerEnabled ? 'primary-button' : 'secondary-button'}
                  type="button"
                  onClick={toggleBackgroundRunner}
                >
                  {autoRunnerEnabled ? 'Auto on' : 'Auto off'}
                </button>
                <span className="status-badge running">{latestScan?.phase ?? 'Idle'}</span>
              </div>
            </div>
            <form className="scan-form" onSubmit={submitScanForm}>
              <label>
                <span>Project</span>
                <select
                  onChange={(event) => {
                    const projectId = event.target.value;
                    const nextTarget = targets.find((target) => target.project_id === projectId);
                    setScanForm({
                      ...scanForm,
                      project_id: projectId,
                      target_id: nextTarget?.id || ''
                    });
                  }}
                  required
                  value={scanForm.project_id}
                >
                  <option value="" disabled>Select project</option>
                  {projects.map((project) => (
                    <option key={project.id} value={project.id}>{project.name}</option>
                  ))}
                </select>
              </label>
              <label>
                <span>Approved target</span>
                <select
                  onChange={(event) => setScanForm({ ...scanForm, target_id: event.target.value })}
                  required
                  value={scanForm.target_id}
                >
                  <option value="" disabled>Select target</option>
                  {scanTargets.map((target) => (
                    <option key={target.id} value={target.id}>{target.name}</option>
                  ))}
                </select>
              </label>
              <label>
                <span>Profile</span>
                <select
                  onChange={(event) => setScanForm({ ...scanForm, profile: event.target.value as ScanFormState['profile'] })}
                  value={scanForm.profile}
                >
                  <option value="safe">Safe active</option>
                  <option value="passive">Passive only</option>
                  <option value="surface">Surface exposure</option>
                </select>
              </label>
              {scanFormError ? <p className="inline-warning">{scanFormError}</p> : null}
              <button className="primary-button" disabled={!scanForm.target_id} type="submit">
                <Play size={16} />
                Queue scan
              </button>
            </form>
            <div className="scan-list">
              {scans.map((scan) => (
                <div className="scan-row" key={scan.id}>
                  <strong>{scan.target_name}</strong>
                  <span>{scan.profile} · {scan.phase}</span>
                  <code>{scan.target_url}</code>
                  {!['completed', 'failed', 'canceled'].includes(scan.phase) ? (
                    <button type="button" onClick={() => cancelScan(scan)}>Cancel</button>
                  ) : (
                    <button type="button" onClick={() => compareScanBaseline(scan)}>
                      <GitBranch size={13} />
                      Baseline
                    </button>
                  )}
                  {baselineDiffs[scan.id] ? (
                    <small>
                      New {baselineDiffs[scan.id].new_findings.length} · Recurring{' '}
                      {baselineDiffs[scan.id].recurring_findings.length} · Resolved{' '}
                      {baselineDiffs[scan.id].resolved_findings.length}
                    </small>
                  ) : null}
                </div>
              ))}
            </div>
          </div>

          <div className="panel">
            <div className="panel-header">
              <div>
                <h2>Local activity</h2>
                <p>All features are free. Scan concurrency remains bounded for safety.</p>
              </div>
              <Gauge size={20} />
            </div>
            <p>Scans this month: {usage.monthly_scans}</p>
            <p>Reports this month: {usage.reports}</p>
            <p>AI guides this month: {usage.ai_fix_guides}</p>
            <p>AI is optional and uses your API key; provider charges may apply.</p>
          </div>
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <h2>Local Engine Service</h2>
              <p>{engine.bind_address} · v{engine.version} · {engine.active_scans}/{engine.max_concurrent_scans} scan slots</p>
            </div>
            <div className="engine-actions">
              <button className="secondary-button" type="button" onClick={() => runEngineCommand('stop_local_engine')}>
                Stop
              </button>
              <button className="primary-button" type="button" onClick={() => runEngineCommand('start_local_engine')}>
                Start
              </button>
            </div>
          </div>
          <div className="engine-checks">
            {engine.checks.map((check) => (
              <div className="engine-check" key={check.component}>
                <span className={`check-dot ${check.status}`} />
                <strong>{check.component}</strong>
                <span>{check.message}</span>
              </div>
            ))}
          </div>
          {engineError ? <p className="inline-warning">{engineError}</p> : null}
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <h2>Local Storage</h2>
              <p>{storage.project_count} projects · {storage.target_count} targets · SQLite persistence</p>
            </div>
            <button className="secondary-button" type="button" onClick={refreshStorageStatus}>
              Refresh
            </button>
          </div>
          <div className="storage-grid">
            <div>
              <strong>Database</strong>
              <code>{storage.database_path}</code>
            </div>
            <div>
              <strong>Migrations</strong>
              <code>{storage.applied_migrations.join(', ')}</code>
            </div>
          </div>
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <h2>Support Diagnostics</h2>
              <p>Generate a redacted local support bundle without secrets, target URLs, or finding evidence.</p>
            </div>
            <button className="secondary-button" type="button" onClick={collectSupportDiagnostics}>
              <FileText size={16} />
              Generate
            </button>
          </div>
          <div className="storage-grid">
            <div>
              <strong>Included</strong>
              <span>version, platform, storage counts, usage, community edition, engine, rule pack, redacted audit logs</span>
            </div>
            <div>
              <strong>Excluded</strong>
              <span>API keys, license keys, approval notes, target URLs, finding evidence, report bodies</span>
            </div>
          </div>
          {supportDiagnosticsMessage ? <p className="inline-note">{supportDiagnosticsMessage}</p> : null}
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <h2>Security Events</h2>
              <p>Recent local audit records with redacted metadata.</p>
            </div>
            <button className="secondary-button" type="button" onClick={refreshAuditLogs}>
              Refresh
            </button>
          </div>
          <div className="audit-table">
            <div className="audit-row audit-head">
              <span>Severity</span>
              <span>Action</span>
              <span>Entity</span>
              <span>Metadata</span>
              <span>Time</span>
            </div>
            {auditLogs.slice(0, 8).map((log) => (
              <div className="audit-row" key={log.id}>
                <span className={`severity ${log.severity}`}>{log.severity}</span>
                <strong>{log.action}</strong>
                <code>{log.entity_type}/{log.entity_id}</code>
                <code>{formatAuditMetadata(log.metadata_json_redacted)}</code>
                <span>{log.created_at}</span>
              </div>
            ))}
            {!auditLogs.length ? <div className="empty-row">No local audit events have been recorded yet.</div> : null}
          </div>
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <h2>AI Provider</h2>
              <p>{maskedApiKey ? `${aiProvider} · ${maskedApiKey}` : 'No session key configured'} · OS secure vault pending</p>
            </div>
            <Sparkles size={20} />
          </div>
          <div className="api-key-grid">
            <label>
              <span>Provider</span>
              <select onChange={(event) => setAiProvider(event.target.value as AiProvider)} value={aiProvider}>
                <option value="openai">OpenAI</option>
                <option value="anthropic">Anthropic</option>
                <option value="custom">Custom endpoint</option>
              </select>
            </label>
            <label>
              <span>User API key</span>
              <input
                autoComplete="off"
                onChange={(event) => setApiKeyDraft(event.target.value)}
                placeholder="Session only"
                type="password"
                value={apiKeyDraft}
              />
            </label>
            <button className="secondary-button" type="button" onClick={saveApiKeySession}>Save session key</button>
            <button className="secondary-button" type="button" onClick={clearApiKeySession}>Clear</button>
          </div>
          {apiKeyError ? <p className="inline-warning">{apiKeyError}</p> : null}
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <h2>Rule Pack Updates</h2>
              <p>
                {rulePackStatus
                  ? `${rulePackStatus.version} · ${rulePackStatus.channel} · ${rulePackStatus.source}`
                  : 'Rule pack status unavailable'}
              </p>
            </div>
            <button className="secondary-button" type="button" onClick={refreshRulePackStatus}>
              Refresh
            </button>
          </div>
          <div className="rule-pack-grid">
            <div>
              <strong>Current manifest</strong>
              <span>{rulePackStatus ? `${rulePackStatus.enabled_rule_count}/${rulePackStatus.rule_count} rules enabled` : 'No manifest loaded'}</span>
              <span>{rulePackStatus?.rollback_available ? 'Rollback available' : 'No rollback snapshot'}</span>
              <span>All supported channels are available without activation</span>
              <code>{rulePackStatus?.manifest_sha256 ? rulePackStatus.manifest_sha256.slice(0, 16) : 'built-in'}</code>
              {rulePackStatus?.bundle_sha256 ? (
                <>
                  <span>{rulePackStatus.bundle_file_name || 'Bundle artifact saved'}</span>
                  <code>{rulePackStatus.bundle_sha256.slice(0, 16)}</code>
                </>
              ) : null}
            </div>
            <label>
              <span>Offline manifest JSON</span>
              <textarea
                onChange={(event) => setRulePackManifest(event.target.value)}
                placeholder="Paste rule pack manifest JSON"
                value={rulePackManifest}
              />
            </label>
            <label>
              <span>Expected SHA-256</span>
              <input
                onChange={(event) => setRulePackExpectedSha256(event.target.value)}
                placeholder="Optional 64-character checksum"
                value={rulePackExpectedSha256}
              />
            </label>
            <div>
              <strong>Signed bundle ZIP</strong>
              <span>{rulePackBundleFile ? `${rulePackBundleFile.name} · ${formatBytes(rulePackBundleFile.size)}` : 'No bundle selected'}</span>
              <label aria-label="Load rule pack bundle" className="file-action" title="Load rule pack bundle">
                <Upload size={16} />
                <input accept=".zip,application/zip" type="file" onChange={loadRulePackBundleFile} />
              </label>
            </div>
            <label>
              <span>Bundle public key</span>
              <input
                onChange={(event) => setRulePackBundlePublicKey(event.target.value)}
                placeholder="Optional Ed25519 public key hex"
                value={rulePackBundlePublicKey}
              />
            </label>
            <label>
              <span>Update feed JSON</span>
              <textarea
                onChange={(event) => setRulePackUpdateFeed(event.target.value)}
                placeholder="Paste rule pack update feed JSON"
                value={rulePackUpdateFeed}
              />
            </label>
            <label>
              <span>Feed public key</span>
              <input
                onChange={(event) => setRulePackFeedPublicKey(event.target.value)}
                placeholder="Optional Ed25519 public key hex"
                value={rulePackFeedPublicKey}
              />
            </label>
            {rulePackFeedStatus ? (
              <div>
                <strong>Feed check</strong>
                <span>{rulePackFeedStatus.update_available ? 'Update available' : 'Current version matches'}</span>
                <span>{rulePackFeedStatus.entitlement_allowed ? 'Channel supported' : rulePackFeedStatus.blocked_reason}</span>
                <span>{rulePackFeedStatus.signature_verified ? 'Signature verified' : 'Signature not checked'}</span>
                <code>{rulePackFeedStatus.manifest_sha256.slice(0, 16)}</code>
              </div>
            ) : null}
          </div>
          <div className="inline-actions">
            <button className="secondary-button" type="button" onClick={loadSampleRulePackManifest}>
              Load sample manifest
            </button>
            <button className="secondary-button" type="button" onClick={loadSampleRulePackUpdateFeed}>
              Load sample feed
            </button>
            <button className="primary-button" type="button" onClick={importRulePackManifest}>
              Import manifest
            </button>
            <button className="primary-button" type="button" onClick={importRulePackBundle}>
              Import bundle
            </button>
            <button className="secondary-button" type="button" onClick={checkRulePackUpdateFeed}>
              Check feed
            </button>
            <button
              className="secondary-button"
              disabled={!rulePackStatus?.rollback_available}
              type="button"
              onClick={rollbackRulePackManifest}
            >
              Roll back
            </button>
          </div>
          {rulePackMessage ? <p className="inline-note">{rulePackMessage}</p> : null}
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <h2>High priority findings</h2>
              <p>{visibleFindings.length}/{findings.length} evidence-backed issues visible.</p>
            </div>
            <AlertTriangle size={20} />
          </div>
          <div className="finding-toolbar">
            <label>
              <span>Search</span>
              <input
                onChange={(event) => setFindingQuery(event.target.value)}
                placeholder="Title, endpoint, status, category"
                value={findingQuery}
              />
            </label>
            <label>
              <span>Severity</span>
              <select
                onChange={(event) => setFindingSeverityFilter(event.target.value as FindingSeverityFilter)}
                value={findingSeverityFilter}
              >
                <option value="all">All severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
            </label>
            <label>
              <span>Status</span>
              <select
                onChange={(event) => setFindingStatusFilter(event.target.value as FindingStatusFilter)}
                value={findingStatusFilter}
              >
                <option value="all">All statuses</option>
                <option value="new">New</option>
                <option value="open">Open</option>
                <option value="accepted_risk">Accepted risk</option>
                <option value="false_positive">False positive</option>
                <option value="resolved">Resolved</option>
              </select>
            </label>
            <label>
              <span>Sort</span>
              <select
                onChange={(event) => setFindingSortKey(event.target.value as FindingSortKey)}
                value={findingSortKey}
              >
                <option value="severity">Severity first</option>
                <option value="status">Status first</option>
                <option value="updated">Recently updated</option>
              </select>
            </label>
          </div>
          <div className="report-summary">
            <SummaryItem label="Critical/High" value={`${findingSummary.criticalHigh}`} />
            <SummaryItem label="Open work" value={`${findingSummary.openWork}`} />
            <SummaryItem label="Accepted risk" value={`${findingSummary.acceptedRisk}`} />
            <SummaryItem label="Resolved" value={`${findingSummary.resolved}`} />
          </div>
          <div className="report-export-row">
            <label>
              <span>Report format</span>
              <select onChange={(event) => setReportFormat(event.target.value as ReportFormat)} value={reportFormat}>
                <option value="html">Branded HTML</option>
                <option value="markdown">Markdown</option>
                <option value="json">JSON</option>
                <option value="pdf">PDF</option>
                <option value="sarif">SARIF</option>
              </select>
            </label>
            <button className="secondary-button" type="button" onClick={exportFindingReport}>
              <Download size={16} />
              Export findings
            </button>
            {reportError ? <p className="inline-warning">{reportError}</p> : null}
          </div>
          <div className="report-history">
            <div className="mini-section-header">
              <strong>Export history</strong>
              <div className="mini-actions">
                <span>{reportHistory.length} local records</span>
                <label className="compact-field">
                  <span>Keep days</span>
                  <input
                    max={3650}
                    min={1}
                    onChange={(event) => setReportRetentionDays(Number(event.target.value))}
                    type="number"
                    value={reportRetentionDays}
                  />
                </label>
                <button className="secondary-button compact-button" type="button" onClick={cleanupOldReportArtifacts}>
                  Clean old
                </button>
              </div>
            </div>
            {reportArtifactMessage ? <p className="inline-note">{reportArtifactMessage}</p> : null}
            <div className="report-history-table">
              <div className="report-history-row report-history-head">
                <span>Format</span>
                <span>Findings</span>
                <span>Size</span>
                <span>SHA-256</span>
                <span>File / audit</span>
                <span>Time</span>
              </div>
              {reportHistory.slice(0, 5).map((log) => {
                const metadata = parseReportAuditMetadata(log.metadata_json_redacted);
                return (
                  <div className="report-history-row" key={log.id}>
                    <span className="report-format">{metadata.format || log.entity_id}</span>
                    <strong>{metadata.findingCount ?? 'n/a'}</strong>
                    <span>{metadata.sizeBytes === null ? 'n/a' : formatBytes(metadata.sizeBytes)}</span>
                    <code>{metadata.sha256 ? metadata.sha256.slice(0, 16) : 'n/a'}</code>
                    <code>{metadata.relativePath || metadata.fileName || log.id}</code>
                    <span>{log.created_at}</span>
                  </div>
                );
              })}
              {!reportHistory.length ? <div className="empty-row">No report exports have been recorded yet.</div> : null}
            </div>
          </div>
          <div className="finding-table">
            <div className="table-row table-head">
              <span>Severity</span>
              <span>Finding</span>
              <span>Endpoint</span>
              <span>Confidence</span>
              <span>Status</span>
            </div>
            {visibleFindings.map((finding) => (
              <button
                className={`table-row finding-row ${selectedFinding?.id === finding.id ? 'selected' : ''}`}
                key={finding.id}
                type="button"
                onClick={() => {
                  setSelectedFindingId(finding.id);
                  setAiGuide(null);
                  setAiGuideMessage(null);
                }}
              >
                <span className={`severity ${finding.severity}`}>{finding.severity}</span>
                <strong>{finding.title}</strong>
                <code>{finding.endpoint}</code>
                <span>{finding.confidence}</span>
                <span>{finding.status}</span>
              </button>
            ))}
            {!visibleFindings.length ? <div className="empty-row">No findings match the current filters.</div> : null}
          </div>
          {selectedFinding ? (
            <div className="finding-detail">
              <div>
                <strong>Evidence</strong>
                <code>{formatEvidence(selectedFinding.evidence_json)}</code>
              </div>
              <div>
                <strong>Remediation</strong>
                <p>{selectedFinding.remediation || 'No remediation text saved yet.'}</p>
              </div>
              <div className="finding-actions">
                <button type="button" onClick={() => changeFindingStatus(selectedFinding, 'open')}>Open</button>
                <button type="button" onClick={() => changeFindingStatus(selectedFinding, 'resolved')}>Resolve</button>
                <button type="button" onClick={() => changeFindingStatus(selectedFinding, 'accepted_risk')}>Accept risk</button>
                <button type="button" onClick={() => changeFindingStatus(selectedFinding, 'false_positive')}>False positive</button>
              </div>
              <div className="ai-fix-guide">
                <div>
                  <strong>AI Fix Guide</strong>
                  <span>Optional · your API key · provider charges may apply</span>
                </div>
                <button type="button" onClick={prepareAiFixGuide}>Generate guide</button>
                <code>{JSON.stringify(aiFixGuideInput, null, 2)}</code>
              </div>
              {aiGuide ? (
                <div className="ai-guide-result">
                  <strong>{aiGuide.summary}</strong>
                  <span>Safe fix steps</span>
                  <ul>{aiGuide.safe_fix_steps.map((step) => <li key={step}>{step}</li>)}</ul>
                  <span>Verification</span>
                  <ul>{aiGuide.verification_steps.map((step) => <li key={step}>{step}</li>)}</ul>
                </div>
              ) : null}
              {aiGuideMessage ? <p className="inline-warning">{aiGuideMessage}</p> : null}
              <div className="finding-meta">
                <span>Source {evidenceSourceLabel(selectedFinding.evidence_json)}</span>
                <span>
                  {evidenceRequiresManualConfirmation(selectedFinding.evidence_json)
                    ? 'Manual confirmation required'
                    : 'Deterministic finding'}
                </span>
                <span>{selectedFinding.parameter_name ? `Parameter ${selectedFinding.parameter_name}` : 'Parameter pending'}</span>
                <span>{selectedFinding.owasp_category || 'OWASP category pending'}</span>
                <span>{selectedFinding.cwe || 'CWE pending'}</span>
                <span>{selectedFinding.created_at || 'Preview evidence'}</span>
              </div>
            </div>
          ) : null}
          {findingError ? <p className="inline-warning">{findingError}</p> : null}
        </section>
      </main>

      <footer className="status-bar">
        <span>Local API 127.0.0.1</span>
        <span>SQLite connected</span>
        <span>Rule pack {rulePackStatus?.version ?? '2026.06.12'}</span>
        <span>CLI aegis-scan</span>
      </footer>
    </div>
  );
}

function Metric({ label, value, subtext, tone }: { label: string; value: string; subtext: string; tone?: string }) {
  return (
    <div className={`metric-card ${tone ?? ''}`}>
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{subtext}</small>
    </div>
  );
}

function ProgressStep({ label, done, active }: { label: string; done?: boolean; active?: boolean }) {
  return (
    <div className={`progress-step ${done ? 'done' : ''} ${active ? 'active' : ''}`}>
      <span />
      <strong>{label}</strong>
    </div>
  );
}

function SummaryItem({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function summarizeFindings(findings: Finding[]) {
  return findings.reduce(
    (summary, finding) => {
      if (finding.severity === 'critical' || finding.severity === 'high') {
        summary.criticalHigh += 1;
      }
      if (finding.status === 'new' || finding.status === 'open') {
        summary.openWork += 1;
      }
      if (finding.status === 'accepted_risk') {
        summary.acceptedRisk += 1;
      }
      if (finding.status === 'resolved') {
        summary.resolved += 1;
      }
      return summary;
    },
    { criticalHigh: 0, openWork: 0, acceptedRisk: 0, resolved: 0 }
  );
}

function buildMarkdownReport({
  findings,
  query,
  severityFilter,
  statusFilter,
  sortKey,
  generatedAt
}: {
  findings: Finding[];
  query: string;
  severityFilter: FindingSeverityFilter;
  statusFilter: FindingStatusFilter;
  sortKey: FindingSortKey;
  generatedAt: Date;
}) {
  const summary = summarizeFindings(findings);
  const lines = [
    '# Aegis WebShield AI Findings Report',
    '',
    `Generated: ${generatedAt.toISOString()}`,
    `Query: ${query.trim() || 'none'}`,
    `Severity filter: ${severityFilter}`,
    `Status filter: ${statusFilter}`,
    `Sort: ${sortKey}`,
    '',
    '## Summary',
    '',
    `- Total findings: ${findings.length}`,
    `- Critical/High: ${summary.criticalHigh}`,
    `- Open work: ${summary.openWork}`,
    `- Accepted risk: ${summary.acceptedRisk}`,
    `- Resolved: ${summary.resolved}`,
    '',
    '## Findings',
    ''
  ];

  for (const finding of findings) {
    lines.push(
      `### ${finding.severity.toUpperCase()} · ${finding.title}`,
      '',
      `- Status: ${finding.status}`,
      `- Confidence: ${finding.confidence}`,
      `- Endpoint: ${formatReportEndpoint(finding.endpoint)}`,
      `- Parameter: ${finding.parameter_name || 'none'}`,
      `- Source: ${evidenceSourceLabel(finding.evidence_json)}`,
      `- Manual confirmation: ${evidenceRequiresManualConfirmation(finding.evidence_json) ? 'required' : 'not required'}`,
      `- OWASP: ${finding.owasp_category || 'pending'}`,
      `- CWE: ${finding.cwe || 'pending'}`,
      '',
      'Evidence:',
      '',
      '```json',
      formatReportEvidence(finding.evidence_json),
      '```',
      '',
      'Remediation:',
      '',
      finding.remediation || 'No remediation text saved yet.',
      ''
    );
  }

  if (!findings.length) {
    lines.push('No findings matched the selected filters.', '');
  }

  return `${lines.join('\n')}\n`;
}

function buildJsonReport(input: {
  findings: Finding[];
  query: string;
  severityFilter: FindingSeverityFilter;
  statusFilter: FindingStatusFilter;
  sortKey: FindingSortKey;
  generatedAt: Date;
}) {
  return {
    product: 'Aegis WebShield AI',
    format: 'aegis.findings.v1',
    generated_at: input.generatedAt.toISOString(),
    filters: {
      query: input.query.trim() || null,
      severity: input.severityFilter,
      status: input.statusFilter,
      sort: input.sortKey
    },
    summary: summarizeFindings(input.findings),
    findings: input.findings.map((finding) => {
      const evidenceMetadata = findingEvidenceMetadata(finding.evidence_json);
      return {
        ...finding,
        endpoint: formatReportEndpoint(finding.endpoint),
        source: evidenceMetadata.source,
        requires_manual_confirmation: evidenceMetadata.requiresManualConfirmation,
        finding_classification: evidenceMetadata.requiresManualConfirmation ? 'candidate' : 'deterministic',
        evidence_json: JSON.stringify(safeReportJsonEvidence(finding.evidence_json))
      };
    })
  };
}

function buildHtmlReport({
  findings,
  query,
  severityFilter,
  statusFilter,
  sortKey,
  generatedAt
}: {
  findings: Finding[];
  query: string;
  severityFilter: FindingSeverityFilter;
  statusFilter: FindingStatusFilter;
  sortKey: FindingSortKey;
  generatedAt: Date;
}) {
  const summary = summarizeFindings(findings);
  const rows = findings
    .map((finding) => {
      const evidence = formatReportEvidence(finding.evidence_json);
      return `
        <article class="finding">
          <div class="finding-head">
            <span class="severity ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span>
            <div>
              <h2>${escapeHtml(finding.title)}</h2>
              <p>${escapeHtml(formatReportEndpoint(finding.endpoint))}</p>
            </div>
          </div>
          <dl>
            <div><dt>Status</dt><dd>${escapeHtml(finding.status)}</dd></div>
            <div><dt>Confidence</dt><dd>${escapeHtml(finding.confidence)}</dd></div>
            <div><dt>Source</dt><dd>${escapeHtml(evidenceSourceLabel(finding.evidence_json))}</dd></div>
            <div><dt>Manual confirmation</dt><dd>${evidenceRequiresManualConfirmation(finding.evidence_json) ? 'required' : 'not required'}</dd></div>
            <div><dt>Parameter</dt><dd>${escapeHtml(finding.parameter_name || 'none')}</dd></div>
            <div><dt>OWASP</dt><dd>${escapeHtml(finding.owasp_category || 'pending')}</dd></div>
            <div><dt>CWE</dt><dd>${escapeHtml(finding.cwe || 'pending')}</dd></div>
          </dl>
          <section>
            <h3>Evidence</h3>
            <pre>${escapeHtml(evidence)}</pre>
          </section>
          <section>
            <h3>Remediation</h3>
            <p>${escapeHtml(finding.remediation || 'No remediation text saved yet.')}</p>
          </section>
        </article>`;
    })
    .join('\n');
  const emptyState = findings.length
    ? ''
    : '<article class="finding"><p>No findings matched the selected filters.</p></article>';

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Aegis WebShield AI Findings Report</title>
  <style>
    :root { color-scheme: light; --ink: #111827; --muted: #5b6472; --line: #d9dee7; --panel: #f7f9fc; --brand: #0f766e; --critical: #b91c1c; --high: #c2410c; --medium: #b45309; --low: #2563eb; --info: #4b5563; }
    * { box-sizing: border-box; }
    body { margin: 0; color: var(--ink); background: #fff; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; line-height: 1.5; }
    main { max-width: 1040px; margin: 0 auto; padding: 40px 32px; }
    header { border-bottom: 3px solid var(--brand); padding-bottom: 20px; margin-bottom: 28px; }
    .brand { color: var(--brand); font-size: 13px; font-weight: 800; letter-spacing: 0; text-transform: uppercase; }
    h1 { margin: 8px 0 8px; font-size: 32px; line-height: 1.15; }
    h2, h3, p { margin-top: 0; }
    .meta, .summary { display: grid; gap: 12px; grid-template-columns: repeat(4, minmax(0, 1fr)); }
    .meta div, .summary div { border: 1px solid var(--line); background: var(--panel); padding: 12px; }
    .meta strong, .summary strong { display: block; font-size: 20px; }
    .meta span, .summary span { color: var(--muted); font-size: 12px; text-transform: uppercase; }
    .finding { page-break-inside: avoid; border: 1px solid var(--line); padding: 18px; margin-top: 18px; }
    .finding-head { display: flex; gap: 14px; align-items: flex-start; border-bottom: 1px solid var(--line); padding-bottom: 12px; margin-bottom: 14px; }
    .finding-head h2 { margin-bottom: 4px; font-size: 20px; }
    .finding-head p { color: var(--muted); margin: 0; overflow-wrap: anywhere; }
    .severity { min-width: 82px; text-align: center; color: white; background: var(--info); padding: 5px 8px; text-transform: uppercase; font-weight: 800; font-size: 12px; }
    .severity.critical { background: var(--critical); }
    .severity.high { background: var(--high); }
    .severity.medium { background: var(--medium); }
    .severity.low { background: var(--low); }
    dl { display: grid; gap: 8px; grid-template-columns: repeat(5, minmax(0, 1fr)); margin: 0 0 14px; }
    dl div { border: 1px solid var(--line); padding: 8px; min-width: 0; }
    dt { color: var(--muted); font-size: 11px; text-transform: uppercase; }
    dd { margin: 2px 0 0; overflow-wrap: anywhere; }
    pre { white-space: pre-wrap; overflow-wrap: anywhere; background: #111827; color: #f9fafb; padding: 12px; font-size: 12px; }
    @media print { main { padding: 20px; } .finding { break-inside: avoid; } }
  </style>
</head>
<body>
  <main>
    <header>
      <div class="brand">Aegis WebShield AI</div>
      <h1>Findings Report</h1>
      <p>Generated ${escapeHtml(generatedAt.toISOString())}</p>
    </header>
    <section class="meta">
      <div><span>Query</span><strong>${escapeHtml(query.trim() || 'none')}</strong></div>
      <div><span>Severity</span><strong>${escapeHtml(severityFilter)}</strong></div>
      <div><span>Status</span><strong>${escapeHtml(statusFilter)}</strong></div>
      <div><span>Sort</span><strong>${escapeHtml(sortKey)}</strong></div>
    </section>
    <section class="summary" aria-label="Summary">
      <div><span>Total</span><strong>${findings.length}</strong></div>
      <div><span>Critical/High</span><strong>${summary.criticalHigh}</strong></div>
      <div><span>Open work</span><strong>${summary.openWork}</strong></div>
      <div><span>Resolved</span><strong>${summary.resolved}</strong></div>
    </section>
    ${rows || emptyState}
  </main>
</body>
</html>`;
}

function buildPdfReport(input: {
  findings: Finding[];
  query: string;
  severityFilter: FindingSeverityFilter;
  statusFilter: FindingStatusFilter;
  sortKey: FindingSortKey;
  generatedAt: Date;
}) {
  const summary = summarizeFindings(input.findings);
  const lines = [
    'Aegis WebShield AI Findings Report',
    `Generated: ${input.generatedAt.toISOString()}`,
    `Query: ${input.query.trim() || 'none'}`,
    `Severity filter: ${input.severityFilter}`,
    `Status filter: ${input.statusFilter}`,
    `Sort: ${input.sortKey}`,
    '',
    `Total findings: ${input.findings.length}`,
    `Critical/High: ${summary.criticalHigh}`,
    `Open work: ${summary.openWork}`,
    `Accepted risk: ${summary.acceptedRisk}`,
    `Resolved: ${summary.resolved}`,
    ''
  ];

  if (!input.findings.length) {
    lines.push('No findings matched the selected filters.');
  }

  input.findings.forEach((finding, index) => {
    lines.push(
      `Finding ${index + 1}: ${finding.severity.toUpperCase()} - ${finding.title}`,
      `Status: ${finding.status}`,
      `Confidence: ${finding.confidence}`,
      `Endpoint: ${formatReportEndpoint(finding.endpoint)}`,
      `Parameter: ${finding.parameter_name || 'none'}`,
      `Source: ${evidenceSourceLabel(finding.evidence_json)}`,
      `Manual confirmation: ${evidenceRequiresManualConfirmation(finding.evidence_json) ? 'required' : 'not required'}`,
      `OWASP: ${finding.owasp_category || 'pending'}`,
      `CWE: ${finding.cwe || 'pending'}`,
      'Evidence:',
      formatReportEvidence(finding.evidence_json),
      'Remediation:',
      finding.remediation || 'No remediation text saved yet.',
      ''
    );
  });

  return renderTextPdf(lines);
}

function buildSarifReport(findings: Finding[]) {
  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'Aegis WebShield AI',
            rules: findings.map((finding) => {
              const evidenceMetadata = findingEvidenceMetadata(finding.evidence_json);
              return {
                id: finding.id,
                name: finding.title,
                shortDescription: { text: finding.title },
                fullDescription: { text: finding.remediation || finding.title },
                properties: {
                  severity: finding.severity,
                  confidence: finding.confidence,
                  status: finding.status,
                  parameter_name: finding.parameter_name,
                  source: evidenceMetadata.source,
                  requires_manual_confirmation: evidenceMetadata.requiresManualConfirmation,
                  finding_classification: evidenceMetadata.requiresManualConfirmation ? 'candidate' : 'deterministic'
                }
              };
            })
          }
        },
        results: findings.map((finding) => {
          const evidenceMetadata = findingEvidenceMetadata(finding.evidence_json);
          return {
            ruleId: finding.id,
            level: sarifLevel(finding.severity),
            message: {
              text: evidenceMetadata.requiresManualConfirmation
                ? `${finding.title} (manual confirmation required)`
                : finding.title
            },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: {
                    uri: formatReportEndpoint(finding.endpoint)
                  }
                }
              }
            ],
            properties: {
              evidence: safeReportJsonEvidence(finding.evidence_json),
              source: evidenceMetadata.source,
              requires_manual_confirmation: evidenceMetadata.requiresManualConfirmation,
              finding_classification: evidenceMetadata.requiresManualConfirmation ? 'candidate' : 'deterministic',
              parameter_name: finding.parameter_name,
              owasp_category: finding.owasp_category,
              cwe: finding.cwe
            }
          };
        })
      }
    ]
  };
}

function renderTextPdf(lines: string[]) {
  const pages = paginatePdfLines(lines);
  const pageCount = pages.length;
  const fontObjectId = 3 + pageCount * 2;
  const objects: string[] = [];
  const pageObjectIds = pages.map((_, index) => 3 + index * 2);

  objects.push('<< /Type /Catalog /Pages 2 0 R >>');
  objects.push(`<< /Type /Pages /Kids [${pageObjectIds.map((id) => `${id} 0 R`).join(' ')}] /Count ${pageCount} >>`);

  pages.forEach((pageLines, index) => {
    const pageObjectId = 3 + index * 2;
    const contentObjectId = pageObjectId + 1;
    const stream = [
      'BT',
      '/F1 10 Tf',
      '50 760 Td',
      '14 TL',
      ...pageLines.map((line) => `(${escapePdfString(line)}) Tj T*`),
      'ET'
    ].join('\n');
    objects.push(
      `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 ${fontObjectId} 0 R >> >> /Contents ${contentObjectId} 0 R >>`
    );
    objects.push(`<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`);
  });

  objects.push('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>');

  let pdf = '%PDF-1.4\n';
  const offsets = [0];
  objects.forEach((object, index) => {
    offsets.push(pdf.length);
    pdf += `${index + 1} 0 obj\n${object}\nendobj\n`;
  });
  const xrefOffset = pdf.length;
  pdf += `xref\n0 ${objects.length + 1}\n`;
  pdf += '0000000000 65535 f \n';
  offsets.slice(1).forEach((offset) => {
    pdf += `${String(offset).padStart(10, '0')} 00000 n \n`;
  });
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF\n`;
  return pdf;
}

function paginatePdfLines(lines: string[]) {
  const wrapped = lines.flatMap((line) => wrapPdfLine(line));
  const pages: string[][] = [];
  for (let index = 0; index < wrapped.length; index += 48) {
    pages.push(wrapped.slice(index, index + 48));
  }
  return pages.length ? pages : [['No report content.']];
}

function wrapPdfLine(line: string) {
  const sanitized = sanitizePdfText(line);
  if (!sanitized) {
    return [''];
  }
  const chunks: string[] = [];
  for (let index = 0; index < sanitized.length; index += 92) {
    chunks.push(sanitized.slice(index, index + 92));
  }
  return chunks;
}

function sanitizePdfText(value: string) {
  return value
    .replace(/[^\x09\x0a\x0d\x20-\x7e]/g, '?')
    .replace(/[\t\r\n]+/g, ' ')
    .trimEnd();
}

function escapePdfString(value: string) {
  return sanitizePdfText(value).replaceAll('\\', '\\\\').replaceAll('(', '\\(').replaceAll(')', '\\)');
}

function escapeHtml(value: string) {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function buildAiFixGuideInput(finding: Finding): AiFixGuideInput {
  const evidenceMetadata = findingEvidenceMetadata(finding.evidence_json);
  return {
    finding_id: finding.id,
    title: finding.title,
    severity: finding.severity,
    endpoint: finding.endpoint,
    evidence: {
      source: evidenceMetadata.source,
      requires_manual_confirmation: evidenceMetadata.requiresManualConfirmation,
      finding_classification: evidenceMetadata.requiresManualConfirmation ? 'candidate' : 'deterministic',
      details: safeJsonEvidence(finding.evidence_json)
    },
    remediation_hint: evidenceMetadata.requiresManualConfirmation
      ? `${finding.remediation || 'No remediation text saved yet.'} Treat this as a candidate and include manual validation before remediation.`
      : finding.remediation || 'No remediation text saved yet.'
  };
}

function sarifLevel(severity: Severity) {
  if (severity === 'critical' || severity === 'high') {
    return 'error';
  }
  if (severity === 'medium') {
    return 'warning';
  }
  return 'note';
}

function safeJsonEvidence(value?: string) {
  if (!value) {
    return null;
  }
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
}

function safeReportJsonEvidence(value?: string): unknown {
  return redactReportJson(safeJsonEvidence(value));
}

function redactReportJson(value: unknown): unknown {
  if (typeof value === 'string') {
    return redactReportText(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactReportJson(item));
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, item]) => [
        key,
        isSensitiveReportKey(key) ? redactSensitiveReportJsonValue(item) : redactReportJson(item)
      ])
    );
  }
  return value;
}

function redactSensitiveReportJsonValue(value: unknown): unknown {
  if (value === null || value === undefined) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactSensitiveReportJsonValue(item));
  }
  if (value && typeof value === 'object') {
    return '[REDACTED]';
  }
  return '[REDACTED]';
}

function isSensitiveReportKey(key: string) {
  return /^(authorization|cookie|set-cookie|api[_-]?key|access[_-]?token|refresh[_-]?token|token|password|secret(?:[_-]?key)?|private[_-]?key)$/i.test(
    key.trim()
  );
}

function evidenceSourceLabel(value?: string) {
  const evidence = safeJsonEvidence(value);
  if (evidence && typeof evidence === 'object' && !Array.isArray(evidence) && 'source' in evidence) {
    const source = (evidence as { source?: unknown }).source;
    if (typeof source === 'string' && source.trim()) {
      return source;
    }
  }
  return 'unknown';
}

function evidenceRequiresManualConfirmation(value?: string) {
  return findingEvidenceMetadata(value).requiresManualConfirmation;
}

function findingEvidenceMetadata(value?: string) {
  return {
    source: evidenceSourceLabel(value),
    requiresManualConfirmation: evidenceRequiresManualConfirmationFromEvidence(safeJsonEvidence(value))
  };
}

function evidenceRequiresManualConfirmationFromEvidence(evidence: unknown) {
  if (evidence && typeof evidence === 'object' && !Array.isArray(evidence) && 'requires_manual_confirmation' in evidence) {
    return (evidence as { requires_manual_confirmation?: unknown }).requires_manual_confirmation === true;
  }
  return false;
}

function filterAndSortFindings(
  findings: Finding[],
  query: string,
  severityFilter: FindingSeverityFilter,
  statusFilter: FindingStatusFilter,
  sortKey: FindingSortKey
) {
  const normalizedQuery = query.trim().toLowerCase();
  return findings
    .filter((finding) => {
      if (severityFilter !== 'all' && finding.severity !== severityFilter) {
        return false;
      }
      if (statusFilter !== 'all' && finding.status !== statusFilter) {
        return false;
      }
      if (!normalizedQuery) {
        return true;
      }
      return [
        finding.title,
        finding.endpoint,
        finding.status,
        finding.confidence,
        finding.owasp_category ?? '',
        finding.cwe ?? ''
      ]
        .join(' ')
        .toLowerCase()
        .includes(normalizedQuery);
    })
    .sort((left, right) => compareFindings(left, right, sortKey));
}

function compareFindings(left: Finding, right: Finding, sortKey: FindingSortKey) {
  if (sortKey === 'status') {
    return statusRank(left.status) - statusRank(right.status) || severityRank(left.severity) - severityRank(right.severity);
  }
  if (sortKey === 'updated') {
    return timestampRank(right.updated_at ?? right.created_at) - timestampRank(left.updated_at ?? left.created_at);
  }
  return severityRank(left.severity) - severityRank(right.severity) || statusRank(left.status) - statusRank(right.status);
}

function severityRank(severity: Severity) {
  return {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4
  }[severity];
}

function statusRank(status: string) {
  return {
    new: 0,
    open: 1,
    accepted_risk: 2,
    false_positive: 3,
    resolved: 4
  }[status] ?? 5;
}

function timestampRank(value?: string) {
  if (!value) {
    return 0;
  }
  const time = Date.parse(value);
  return Number.isNaN(time) ? 0 : time;
}

function maskSecret(value: string) {
  if (value.length <= 8) {
    return '********';
  }
  return `${value.slice(0, 4)}...${value.slice(-4)}`;
}

function toUserError(error: unknown) {
  if (typeof error === 'string' && error.length > 0) {
    return error;
  }
  if (error instanceof Error) {
    return error.message;
  }
  return 'Unable to save changes';
}

function formatEvidence(value?: string) {
  if (!value) {
    return 'No evidence saved yet.';
  }
  try {
    return JSON.stringify(JSON.parse(value), null, 2);
  } catch {
    return value;
  }
}

function formatReportEndpoint(value: string) {
  return redactReportText(value);
}

function formatReportEvidence(value?: string) {
  if (!value) {
    return 'No evidence saved yet.';
  }
  try {
    return JSON.stringify(safeReportJsonEvidence(value), null, 2);
  } catch {
    return redactReportText(value);
  }
}

function redactReportText(value: string) {
  return value
    .replace(/https?:\/\/[^\s"'<>]+/gi, (match) => redactReportUrl(match))
    .replace(/(authorization\s*[:=]\s*bearer\s+)[^\s"',;}]+/gi, '$1[REDACTED]')
    .replace(
      /((?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|password|secret(?:[_-]?key)?|private[_-]?key)\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,;}]+)/gi,
      '$1[REDACTED]'
    )
    .replace(/(set-cookie\s*[:=]\s*)[^\r\n]+/gi, '$1[REDACTED]')
    .replace(/(cookie\s*[:=]\s*)[^\r\n]+/gi, '$1[REDACTED]');
}

function redactReportUrl(value: string) {
  const trailing = value.match(/[),.;\]]+$/)?.[0] ?? '';
  const core = trailing ? value.slice(0, -trailing.length) : value;
  try {
    const url = new URL(core);
    const parameterNames = Array.from(new Set(Array.from(url.searchParams.keys()).filter(Boolean))).sort();
    url.search = '';
    url.hash = '';
    parameterNames.forEach((name) => url.searchParams.append(name, ''));
    return `${url.toString()}${trailing}`;
  } catch {
    return value;
  }
}

function formatAuditMetadata(value: string) {
  try {
    return JSON.stringify(JSON.parse(value));
  } catch {
    return value;
  }
}

function buildReportArtifactMetadata(extension: string): ReportArtifactMetadata {
  const timestamp = new Date().toISOString().replaceAll(':', '-').replaceAll('.', '-');
  return {
    fileName: `aegis-webshield-findings-${timestamp}.${extension}`
  };
}

function parseReportAuditMetadata(value: string) {
  try {
    const parsed = JSON.parse(value) as {
      artifact_file_name?: unknown;
      artifact_relative_path?: unknown;
      artifact_sha256?: unknown;
      artifact_size_bytes?: unknown;
      finding_count?: unknown;
      format?: unknown;
    };
    return {
      format: typeof parsed.format === 'string' ? parsed.format : null,
      findingCount: typeof parsed.finding_count === 'number' ? parsed.finding_count : null,
      fileName: typeof parsed.artifact_file_name === 'string' ? parsed.artifact_file_name : null,
      relativePath: typeof parsed.artifact_relative_path === 'string' ? parsed.artifact_relative_path : null,
      sha256: typeof parsed.artifact_sha256 === 'string' ? parsed.artifact_sha256 : null,
      sizeBytes: typeof parsed.artifact_size_bytes === 'number' ? parsed.artifact_size_bytes : null
    };
  } catch {
    return {
      format: null,
      findingCount: null,
      fileName: null,
      relativePath: null,
      sha256: null,
      sizeBytes: null
    };
  }
}

function formatBytes(value: number) {
  if (value < 1024) {
    return `${value} B`;
  }
  if (value < 1024 * 1024) {
    return `${Math.round(value / 102.4) / 10} KB`;
  }
  return `${Math.round(value / 104857.6) / 10} MB`;
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
