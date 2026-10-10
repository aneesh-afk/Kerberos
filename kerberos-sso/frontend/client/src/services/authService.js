const API_URL = import.meta.env.VITE_CORE_API_URL;

// Temporary mock mode.
// Change this to false when Group 1's Core API is ready.
const USE_MOCK_API = true;

export async function registerUser(username, password) {
  if (USE_MOCK_API) {
    // Mock response based on the API contract:
    // { user_id }
    return {
      user_id: "mock-user-123",
    };
  }

  const response = await fetch(`${API_URL}/auth/register`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      username,
      password,
    }),
  });

  if (!response.ok) {
    throw new Error("Registration failed");
  }

  return response.json();
}

export async function loginUser(username, password) {
  if (USE_MOCK_API) {
    // Mock response based on the API contract:
    // { session_token }
    return {
      session_token: "mock-session-token-123",
    };
  }

  const response = await fetch(`${API_URL}/auth/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      username,
      password,
    }),
  });

  if (!response.ok) {
    throw new Error("Login failed");
  }

  return response.json();
}

export async function logoutUser(sessionToken) {
  if (USE_MOCK_API) {
    // Mock response based on the API contract:
    // HTTP 204
    return true;
  }

  const response = await fetch(`${API_URL}/auth/logout`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${sessionToken}`,
    },
  });

  if (!response.ok) {
    throw new Error("Logout failed");
  }

  return true;
}