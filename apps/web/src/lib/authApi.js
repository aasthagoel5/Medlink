import apiClient from './apiClient'

export const signup = async ({name, email, password }) => {
  const res= await apiClient.post('/auth/signup', {name, email, password})
  return res.data
}

export const login = async ({email, password}) => {
  const res= await apiClient.post('/auth/login', {email, password})
  return res.data
}

