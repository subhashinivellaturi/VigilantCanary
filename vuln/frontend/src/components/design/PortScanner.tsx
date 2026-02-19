import React, { useState } from 'react';
import { SecurityCard } from './SecurityCard';
import { useToast } from '../ui/Toast';

export interface PortScannerForm {
  host: string;
  port: number | '';
  protocol: 'tcp' | 'udp';
}

/**
 * PortScanner component with client-side validation and toast feedback
 */
export const PortScanner: React.FC = () => {
  const [form, setForm] = useState<PortScannerForm>({ host: '', port: '', protocol: 'tcp' });
  const [loading, setLoading] = useState(false);
  const { showToast } = useToast();

  const setField = <K extends keyof PortScannerForm>(k: K, v: PortScannerForm[K]) => setForm((s) => ({ ...s, [k]: v }));

  const validate = () => {
    if (!form.host.trim()) return 'Host is required';
    const port = Number(form.port);
    if (Number.isNaN(port) || port < 1 || port > 65535) return 'Port must be between 1 and 65535';
    return null;
  };

  const handleScan = async () => {
    const err = validate();
    if (err) return showToast(err, 'error');
    setLoading(true);
    // simulate API call
    setTimeout(() => {
      setLoading(false);
      showToast(`Scan completed for ${form.host}:${form.port}`, 'success');
    }, 900);
  };

  return (
    <SecurityCard title="Port Scanner" subtitle="Quick scan of a single host and port">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 items-end">
        <div className="md:col-span-2">
          <label className="text-sm text-slate-300 block mb-1">Host</label>
          <input value={form.host} onChange={(e) => setField('host', e.target.value)} placeholder="example.com" className="w-full p-2 rounded-md bg-slate-800 border border-slate-700" />
        </div>

        <div>
          <label className="text-sm text-slate-300 block mb-1">Port</label>
          <input type="number" value={form.port === '' ? '' : form.port} onChange={(e) => setField('port', e.target.value === '' ? '' : Number(e.target.value))} placeholder="443" className="w-full p-2 rounded-md bg-slate-800 border border-slate-700" />
        </div>

        <div className="md:col-span-3 flex gap-3">
          <select value={form.protocol} onChange={(e) => setField('protocol', e.target.value as 'tcp' | 'udp')} className="rounded-md bg-slate-800 border border-slate-700 p-2">
            <option value="tcp">TCP</option>
            <option value="udp">UDP</option>
          </select>

          <button onClick={handleScan} disabled={loading} className={`ml-auto px-4 py-2 rounded-md ${loading ? 'bg-slate-700' : 'bg-emerald-600 hover:bg-emerald-500'}`}>
            {loading ? 'Scanning...' : 'Scan'}
          </button>
        </div>
      </div>
    </SecurityCard>
  );
};
