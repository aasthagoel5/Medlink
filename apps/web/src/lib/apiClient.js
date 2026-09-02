import axios from "axios"

const apiClient = axios.create({
  baseURL: 'http://localhost:5000',
})

// automatically attach the JWT token to every request, once we have one
apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('medlink_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

export default apiClient