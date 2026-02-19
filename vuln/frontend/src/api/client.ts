import type { HealthStatus, ScanRequest, ScanResponse, AttackClassification, RemediationResponse } from "../types";

const API_URL = import.meta.env.VITE_API_URL ?? "http://localhost:8007/api/v1";

// Export API_URL for use in other components
export { API_URL };

// Utility function to validate URL
function validateUrl(urlString: string): boolean {
  if (!urlString || typeof urlString !== "string" || urlString.trim() === "") {
    return false;
  }
  try {
    new URL(urlString);
    return true;
  } catch {
    return false;
  }
}

// Utility function to validate payload
function validatePayload(payload: string): boolean {
  return payload != null && typeof payload === "string" && payload.trim().length > 0;
}

// Utility function to safely get response data with validation
function validateResponseData(data: unknown): ScanResponse | null {
  if (!data || typeof data !== "object") {
    return null;
  }
  
  const response = data as any;
  
  // Check for required fields
  if (response.label == null || response.probability == null) {
    return null;
  }
  
  // Safely ensure arrays exist
  if (!Array.isArray(response.feature_insights)) {
    response.feature_insights = [];
  }
  if (!Array.isArray(response.suggestions)) {
    response.suggestions = [];
  }
  
  return response as ScanResponse;
}

export async function analyzePayload(payload: ScanRequest): Promise<ScanResponse> {
  try {
    // Validate inputs before sending
    if (!validateUrl(payload.url)) {
      throw new Error("Invalid or empty URL provided. Please enter a valid URL (e.g., https://example.com)");
    }
    
    if (!validatePayload(payload.payload)) {
      throw new Error("Invalid or empty payload provided. Please enter a payload to scan");
    }

    const res = await fetch(`${API_URL}/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      throw new Error(`Scan failed (${res.status}): ${res.statusText}`);
    }

    const responseData = await res.json();
    const validatedData = validateResponseData(responseData);
    
    if (!validatedData) {
      throw new Error("Invalid response from server: missing required fields");
    }

    return validatedData;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Backend unavailable or validation failed. Ensure backend is running on ${API_URL} — Error: ${msg}`);
  }
}

export async function classifyAttack(url: string, payload: string): Promise<AttackClassification> {
  try {
    // Validate inputs before sending
    if (!validateUrl(url)) {
      throw new Error("Invalid or empty URL provided. Please enter a valid URL");
    }
    
    if (!validatePayload(payload)) {
      throw new Error("Invalid or empty payload provided. Please enter a payload to classify");
    }

    const res = await fetch(`${API_URL}/classify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, payload }),
    });

    if (!res.ok) {
      throw new Error(`Classification failed (${res.status}): ${res.statusText}`);
    }

    const data = await res.json();
    
    // Validate response structure
    if (!data || typeof data !== "object" || data.attack_type == null) {
      throw new Error("Invalid response from server: missing attack_type");
    }
    
    // Ensure risk_indicators is an array
    if (!Array.isArray(data.risk_indicators)) {
      data.risk_indicators = [];
    }
    
    return data as AttackClassification;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Attack classification failed. Error: ${msg}`);
  }
}

export async function remediateCode(
  code_snippet: string,
  vulnerability_type: string,
  language: string,
  url?: string,
  raw_payload?: string
): Promise<RemediationResponse> {
  try {
    // Validate required inputs
    if (!code_snippet || typeof code_snippet !== "string" || code_snippet.trim() === "") {
      throw new Error("Code snippet is required for remediation");
    }
    
    if (!vulnerability_type || typeof vulnerability_type !== "string" || vulnerability_type.trim() === "") {
      throw new Error("Vulnerability type is required");
    }
    
    if (!language || typeof language !== "string" || language.trim() === "") {
      throw new Error("Programming language is required");
    }

    const body: any = { code_snippet, vulnerability_type, language };
    if (url && validateUrl(url)) {
      body.url = url;
    }
    if (raw_payload && validatePayload(raw_payload)) {
      body.raw_payload = raw_payload;
    }

    const res = await fetch(`${API_URL}/remediate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      throw new Error(`Remediation request failed (${res.status}): ${res.statusText}`);
    }

    const data = await res.json();
    
    // Validate response structure
    if (!data || typeof data !== "object") {
      throw new Error("Invalid response from server");
    }
    
    // Ensure arrays exist
    if (!Array.isArray(data.vulnerable_lines)) {
      data.vulnerable_lines = [];
    }
    
    return data as RemediationResponse;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Remediation request failed. Error: ${msg}`);
  }
}

export async function fetchHealth(): Promise<HealthStatus> {
  const res = await fetch(`${API_URL}/health`);
  if (!res.ok) {
    throw new Error("Health check failed");
  }
  return (await res.json()) as HealthStatus;
}
