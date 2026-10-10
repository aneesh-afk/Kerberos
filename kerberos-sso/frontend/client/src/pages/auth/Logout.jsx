import { useState } from "react";
import { logoutUser } from "../../services/authService";

function Logout() {
  const [message, setMessage] = useState("");

  const handleLogout = async () => {
    try {
      const sessionToken = "mock-session-token-123";

      await logoutUser(sessionToken);

      setMessage("Logout successful!");
    } catch (error) {
      setMessage(error.message);
    }
  };

  return (
    <div>
      <h1>Logout</h1>

      <button onClick={handleLogout}>
        Logout
      </button>

      {message && <p>{message}</p>}
    </div>
  );
}

export default Logout;