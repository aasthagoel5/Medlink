import apiClient from "./apiClient";

export const createShareLink = async ({ recordId, expiry }) => {
  const res = await appClient.post('/sharing', {recordId, expiry })
  return res.data
}

export const getActivelink = async() =>{
  const res = await appClient.get('/sharing/active')
  return res.data
}

export const revokeLink = async(id) =>{
  const res = await appClient.delete(`/sharing'/${id}`)
  return res.data
}