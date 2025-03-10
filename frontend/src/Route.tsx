import { createBrowserRouter, Navigate } from "react-router";
import App from "./App";
import HomePage from "./pages/HomePage";
import ProtectedPage from "./pages/ProtectedPage";

export const router = createBrowserRouter([
    {
        path: "/",
        element: <App/>,
        children: [
            {path: "", element: <HomePage/>},
            {path: "/protected", element: <ProtectedPage/>},
            {path: "*", element: <Navigate replace to="/"/>}
        ]
    }
]);