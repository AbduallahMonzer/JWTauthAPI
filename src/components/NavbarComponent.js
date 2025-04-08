import React from "react";
import { Navbar, Container } from "react-bootstrap";

const NavbarComponent = () => {
  return (
    <Navbar bg="light" expand="lg">
      <Container>
        <Navbar.Brand href="/">Life Capital</Navbar.Brand>
      </Container>
    </Navbar>
  );
};

export default NavbarComponent;
