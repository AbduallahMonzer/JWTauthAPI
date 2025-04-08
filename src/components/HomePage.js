import React, { useEffect, useState } from "react";
import { Container, Button, Row, Col, Spinner } from "react-bootstrap";
import NavbarComponent from "./NavbarComponent";

const HomePage = () => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("http://localhost:5121/api/list_users", {
      method: "GET",
      credentials: "include",
    })
      .then((res) => {
        if (!res.ok) {
          throw new Error("Unauthorized");
        }
        return res.json();
      })
      .then((data) => {
        setUser(data);
        setLoading(false);
      })
      .catch((err) => {
        console.error("Error fetching user info:", err);
        setLoading(false);
      });
  }, []);

  if (loading) {
    return (
      <Container className="text-center mt-5">
        <Spinner animation="border" />
      </Container>
    );
  }

  return (
    <>
      <NavbarComponent />
      <Container className="mt-5 text-center">
        <Row className="justify-content-center">
          <Col md={8}>
            <h1>Welcome to Life Capital 👋</h1>
            {user && (
              <p>
                Hello, <strong>{user.username}</strong>!
              </p>
            )}

            <div className="mt-4">
              <Button variant="primary" href="/profile" className="mx-2">
                Complete Your Profile
              </Button>

              {user?.role === "admin" && (
                <Button variant="warning" href="/list-users" className="mx-2">
                  List Users
                </Button>
              )}
            </div>
          </Col>
        </Row>
      </Container>
    </>
  );
};

export default HomePage;
