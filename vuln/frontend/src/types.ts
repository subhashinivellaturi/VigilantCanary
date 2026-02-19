export type Severity = "low" | "medium" | "high";

export interface FeatureInsight {
  feature: string;
  contribution: number;
}

export interface FixSuggestion {
  title: string;
  description: string;
  reference: string;
}

export interface ScanResponse {
  timestamp: string;
  label: string;
  probability: number;
  severity: Severity;
  anomaly_score: number;
  feature_insights: FeatureInsight[];
  suggestions: FixSuggestion[];
  cvss_score?: number | null;
}

export interface ScanRequest {
  url: string;
  payload: string;
  metadata?: {
    framework?: string;
    code_language?: string;
    notes?: string;
  };
}

export interface AccuracyPoint {
  label: string;
  accuracy: number;
}

export interface ModelSnapshot {
  accuracy: number;
  precision: number;
  recall: number;
  f1: number;
  history?: AccuracyPoint[];
}

export interface HealthStatus {
  status: string;
  model_version: string;
  dataset_size: number;
  metrics?: Partial<ModelSnapshot>;
}

export interface AttackClassification {
  attack_type: string;
  confidence: number;
  description: string;
  risk_indicators: string[];
}

export interface RemediationResponse {
  vulnerability_type: string;
  vulnerable_lines: number[];
  explanation: string;
  secure_code: string;
  why_it_works: string;
}
// Sequential Workflow Types
export interface RemediationStep {
  priority: number;
  title: string;
  description: string;
  code_example: string;
  reference: string;
}

export interface VulnerabilityIndicator {
  indicator_type: string;
  severity_factor: number;
  confidence: number;
  description: string;
}

export interface Step1Result {
  status: string;
  url: string;
  is_safe: boolean;
  vulnerability_locations: string[];
  indicators: VulnerabilityIndicator[];
  explanation: string;
  remediation_steps: RemediationStep[];
  risk_level_if_unsafe: string;
  proceed_to_step2: boolean;
}

export interface Step2Result {
  status: string;
  payload_safe: boolean;
  combined_risk: string;
  vulnerability_locations: string[];
  indicators: VulnerabilityIndicator[];
  explanation: string;
  remediation_steps: RemediationStep[];
  attack_vectors_detected: string[];
}

export interface Step3Result {
  risk_level: string;
  risk_score: number;
  justification: string;
  contributing_factors: string[];
}

export interface Step4Result {
  detailed_explanation: string;
  vulnerable_areas: string[];
  best_practices: string[];
  references: string[];
}

export interface Step5Result {
  priority_remediations: RemediationStep[];
  short_term_actions: string[];
  long_term_strategy: string[];
  compliance_requirements: string[];
  estimated_effort: string;
  summary: string;
}

export interface SequentialWorkflowResponse {
  step1: Step1Result;
  step2: Step2Result | null;
  step3: Step3Result;
  step4: Step4Result;
  step5: Step5Result;
  workflow_completed: boolean;
  status_message: string;
}