import apiClient from "./apiClient";

export const getProfile = async () => {
  const res = await apiClient.get('/users/profile');
  return res.data;
}

export const updateProfile = async (profileData) => {
  const res = await apiClient.put('/users/profile', profileData);
  return res.data;
}
