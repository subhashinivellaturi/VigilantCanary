import { useState } from "react";
import { analyzePayload } from "../api/client";
import type { ScanRequest, ScanResponse } from "../types";

export function useScan() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResponse | null>(null);

  async function submitScan(payload: ScanRequest) {
    try {
      setLoading(true);
      setError(null);
      const response = await analyzePayload(payload);
      setResult(response);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }

  return { loading, error, result, submitScan, setResult };
}
