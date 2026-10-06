import React, { useState } from 'react';
import { uploadFileScan, submitRawScan } from '../api';

const SAMPLE_DOCKERFILE = `# Sample Misconfigured Dockerfile
FROM ubuntu:latest

ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

WORKDIR /root

ADD https://example.com/downloads/archive.tar.gz /tmp/

EXPOSE 22
EXPOSE 80 443/tcp

# Missing USER directive (runs as root)
CMD ["/bin/bash"]`;

const SAMPLE_K8S_POD = `apiVersion: v1
kind: Pod
metadata:
  name: privileged-debug-pod
  namespace: default
spec:
  hostNetwork: true
  hostPID: true
  hostIPC: true
  containers:
    - name: debug-tools
      image: ubuntu:latest
      securityContext:
        privileged: true
        allowPrivilegeEscalation: true
        runAsUser: 0
        capabilities:
          add:
            - SYS_ADMIN
            - NET_ADMIN`;

export default function NewScanView({ onScanComplete }) {
  const [file, setFile] = useState(null);
  const [rawContent, setRawContent] = useState('');
  const [filename, setFilename] = useState('pasted_config.yaml');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      const selected = e.target.files[0];
      setFile(selected);
      setFilename(selected.name);
    }
  };

  const handleRunScan = async () => {
    setLoading(true);
    setError(null);

    try {
      let result;
      if (file) {
        result = await uploadFileScan(file);
      } else if (rawContent.trim()) {
        result = await submitRawScan(rawContent, filename);
      } else {
        throw new Error('Please select a file or paste configuration content before scanning.');
      }

      if (result && result.id) {
        onScanComplete(result.id);
      } else {
        throw new Error('Scan returned invalid response.');
      }
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Scan failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto font-sans text-[#EDEDED]">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-[#EDEDED] font-sans tracking-tight">Initialize New Security Scan</h2>
          <p className="text-sm text-[#A3A3A3] mt-1 font-sans">
            Upload configuration files or paste raw manifests to analyze security posture via OPA Rego policies.
          </p>
        </div>
        <div className="flex items-center gap-2 text-[#EDEDED] font-mono text-xs border border-[#262626] px-3 py-1 rounded bg-[#121212]">
          <span className="material-symbols-outlined text-sm text-[#10B981]">check_circle</span>
          Engine Ready
        </div>
      </div>

      {error && (
        <div className="p-4 bg-[#271113] border border-[#7F1D1D] rounded text-[#EF4444] font-sans text-xs flex items-center justify-between">
          <span>{error}</span>
          <button onClick={() => setError(null)} className="text-[#EF4444] font-bold hover:underline">Dismiss</button>
        </div>
      )}

      {/* Split Input Layout */}
      <div className="grid grid-cols-12 gap-6 min-h-[420px]">
        {/* Drag & Drop File Upload */}
        <div className="col-span-12 lg:col-span-5 bg-[#121212] rounded-xl p-6 border border-[#262626] flex flex-col">
          <h3 className="text-base font-bold text-[#EDEDED] font-sans mb-3 flex items-center gap-2">
            <span className="material-symbols-outlined text-[#EDEDED]">upload_file</span>
            Option A: File Upload
          </h3>

          <div className="flex-1 border border-dashed border-[#262626] rounded-lg bg-[#050505] flex flex-col items-center justify-center p-6 text-center hover:border-[#525252] transition-all relative">
            <input
              type="file"
              onChange={handleFileChange}
              accept=".yaml,.yml,.json,Dockerfile,text/plain"
              className="absolute inset-0 w-full h-full opacity-0 cursor-pointer z-10"
            />
            <span className="material-symbols-outlined text-4xl text-[#A3A3A3] mb-3">cloud_upload</span>
            <p className="font-sans text-sm font-semibold text-[#EDEDED] mb-1">
              {file ? file.name : 'Drag & drop your file here'}
            </p>
            <p className="font-mono text-xs text-[#737373] mb-4">
              {file ? `${(file.size / 1024).toFixed(1)} KB` : 'Supports Dockerfile, K8s YAML, JSON'}
            </p>
            <button className="bg-[#171717] text-[#EDEDED] border border-[#262626] font-sans text-xs font-semibold px-4 py-2 rounded hover:bg-[#262626] transition-colors">
              {file ? 'Change Selected File' : 'Browse Local Files'}
            </button>
          </div>
        </div>

        {/* Raw Code Editor */}
        <div className="col-span-12 lg:col-span-7 bg-[#121212] rounded-xl p-6 border border-[#262626] flex flex-col">
          <div className="flex justify-between items-center mb-3">
            <h3 className="text-base font-bold text-[#EDEDED] font-sans flex items-center gap-2">
              <span className="material-symbols-outlined text-[#EDEDED]">code</span>
              Option B: Paste Configuration
            </h3>
            <div className="flex gap-2 font-mono text-xs">
              <button
                onClick={() => {
                  setRawContent(SAMPLE_DOCKERFILE);
                  setFilename('Dockerfile');
                  setFile(null);
                }}
                className="text-[#EDEDED] px-2.5 py-1 border border-[#262626] rounded bg-[#171717] hover:bg-[#262626] transition-all cursor-pointer"
              >
                + Preset Dockerfile
              </button>
              <button
                onClick={() => {
                  setRawContent(SAMPLE_K8S_POD);
                  setFilename('pod.yaml');
                  setFile(null);
                }}
                className="text-[#EDEDED] px-2.5 py-1 border border-[#262626] rounded bg-[#171717] hover:bg-[#262626] transition-all cursor-pointer"
              >
                + Preset K8s Pod
              </button>
              <button
                onClick={() => setRawContent('')}
                className="text-[#A3A3A3] hover:text-[#EDEDED] px-2 py-1 border border-[#262626] rounded"
              >
                Clear
              </button>
            </div>
          </div>

          <div className="flex-1 bg-[#050505] rounded border border-[#262626] p-3 font-mono text-xs">
            <textarea
              value={rawContent}
              onChange={(e) => {
                setRawContent(e.target.value);
                setFile(null);
              }}
              placeholder="Paste raw Dockerfile or Kubernetes YAML manifest content here..."
              spellCheck="false"
              className="w-full h-full min-h-[260px] bg-transparent text-[#EDEDED] placeholder-[#737373] resize-none border-none focus:outline-none focus:ring-0 font-mono"
            />
          </div>
        </div>
      </div>

      {/* Action Footer */}
      <div className="bg-[#121212] rounded-xl p-5 border border-[#262626] flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className="material-symbols-outlined text-[#EDEDED]">gavel</span>
          <div className="font-mono text-xs text-[#A3A3A3]">
            Target File: <span className="text-[#EDEDED] font-bold">{file ? file.name : filename}</span>
          </div>
        </div>

        <button
          onClick={handleRunScan}
          disabled={loading}
          className="bg-[#EDEDED] text-[#0A0A0A] font-sans text-sm font-bold px-6 py-2.5 rounded hover:bg-[#FFFFFF] transition-all flex items-center gap-2 disabled:opacity-50 cursor-pointer shadow-sm"
        >
          {loading ? (
            <>
              <span className="material-symbols-outlined animate-spin text-base">progress_activity</span>
              Running OPA Audit...
            </>
          ) : (
            <>
              <span className="material-symbols-outlined text-base">play_arrow</span>
              Run Security Scan
            </>
          )}
        </button>
      </div>
    </div>
  );
}
