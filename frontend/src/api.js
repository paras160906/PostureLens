import axios from 'axios';

const API_BASE_URL = 'http://localhost:8000';

export const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Accept': 'application/json',
  },
});

export const fetchScans = async () => {
  const response = await api.get('/scans');
  return response.data;
};

export const fetchScanDetail = async (id) => {
  const response = await api.get(`/scans/${id}`);
  return response.data;
};

export const fetchPolicies = async () => {
  const response = await api.get('/policies');
  return response.data;
};

export const uploadFileScan = async (file) => {
  const formData = new FormData();
  formData.append('file', file);
  const response = await api.post('/scan', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  });
  return response.data;
};

export const submitRawScan = async (content, filename = 'pasted_config.yaml') => {
  const blob = new Blob([content], { type: 'text/plain' });
  const file = new File([blob], filename, { type: 'text/plain' });
  return uploadFileScan(file);
};

export const fetchRuntimeAlerts = async () => {
  const response = await api.get('/runtime-alerts');
  return response.data;
};

export const simulateFalcoAlert = async () => {
  const response = await api.post('/falco/simulate');
  return response.data;
};
