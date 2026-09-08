import apiClient from "./apiClient";

export const createShareLink = async ({ recordId, expiry }) => {
  const res = await apiClient.post('/sharing', {recordId, expiry })
  return res.data
}

export const getActiveLink = async() =>{
  const res = await apiClient.get('/sharing/active')
  return res.data
}

export const revokeLink = async(id) =>{
  const res = await apiClient.delete(`/sharing/${id}`)
  return res.data
}