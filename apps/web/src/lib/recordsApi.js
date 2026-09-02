import apiClient from './apiClient'

export const getRecords = async () => {
  const res = await apiClient.get('/records')
  return res.data
}

export const getRecordById = async (id) => {
  const res = await apiClient.get(`/records/${id}`)
  return res.data
}

export const deleteRecord = async (id) => {
  const res = await apiClient.delete(`/records/${id}`)
  return res.data
}

export const createRecord = async (formData) => {
  // formData must be a FormData object — file upload, not JSON
  const res = await apiClient.post('/records', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  })
  return res.data
}