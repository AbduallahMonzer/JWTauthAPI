import React from "react";
import { BrowserRouter as Router, Route, Routes } from "react-router-dom";
import AuthRegister from "./components/AuthRegister.js";
import HomePage from "./components/HomePage.js";
import ListUsers from "./components/ListUsers.js";

const App = () => {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<AuthRegister isLogin={true} />} />
        <Route path="/login" element={<AuthRegister isLogin={true} />} />
        <Route path="/signup" element={<AuthRegister isLogin={false} />} />
        <Route path="/home" element={<HomePage />} />
        <Route path="/list-users" element={<ListUsers />} />
        <Route path="*" element={<h1>404 - Page Not Found</h1>} />
      </Routes>
    </Router>
  );
};

export default App;
