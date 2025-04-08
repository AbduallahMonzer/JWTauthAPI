import React, { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { Form, Button, Container, Row, Col, Alert } from "react-bootstrap";
import "bootstrap/dist/css/bootstrap.min.css";

const AuthRegister = ({ isLogin }) => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [errorMessage, setErrorMessage] = useState("");

  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();

    const url = isLogin ? "/auth/login" : "/auth/signup";

    try {
      const response = await fetch(`http://localhost:5121${url}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          username,
          password,
        }),
      });

      if (response.ok) {
        const data = await response.json();
        localStorage.setItem("token", data.token);
        navigate("/home");
      } else {
        setErrorMessage("Failed to authenticate");
      }
    } catch (error) {
      setErrorMessage("An error occurred, please try again");
    }
  };

  return (
    <Container className="d-flex justify-content-center align-items-center min-vh-100">
      <Row className="justify-content-center w-100">
        <Col md={6} lg={4}>
          <div className="text-center mb-4">
            <img
              src="/Images/Logo.png"
              alt="Logo"
              className="img-fluid mx-auto d-block"
              style={{ width: "150px" }}
            />
          </div>

          <h2 className="text-center mb-4">{isLogin ? "Login" : "Sign Up"}</h2>

          {errorMessage && <Alert variant="danger">{errorMessage}</Alert>}

          <Form onSubmit={handleSubmit}>
            <Form.Group className="mb-3" controlId="formUsername">
              <Form.Label>Username</Form.Label>
              <Form.Control
                type="text"
                placeholder="Enter your username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
              />
            </Form.Group>

            <Form.Group className="mb-3" controlId="formPassword">
              <Form.Label>Password</Form.Label>
              <Form.Control
                type="password"
                placeholder="Enter your password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </Form.Group>

            <Button variant="primary" type="submit" className="w-100">
              {isLogin ? "Login" : "Sign Up"}
            </Button>
          </Form>

          <div className="text-center mt-3">
            {isLogin ? (
              <>
                Don't have an account? <Link to="/signup">Sign Up</Link>
              </>
            ) : (
              <>
                Already have an account? <Link to="/login">Login</Link>
              </>
            )}
          </div>
        </Col>
      </Row>
    </Container>
  );
};

export default AuthRegister;
