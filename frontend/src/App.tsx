import { createTheme, ThemeProvider } from "@mui/material";
import CssBaseline from "@mui/material/CssBaseline";
import { Outlet} from "react-router";
import { Layout } from "./layout";

function App() {
  const isDarkMode = true;
  const theme = createTheme({
    palette: {
      mode: isDarkMode ? `dark` : `light`,
    }
  });
  return (
    <>
      <ThemeProvider theme={theme}>
        <CssBaseline/>
        <Layout>
          <Outlet/>
        </Layout>
      </ThemeProvider>

    </>
  )
}

export default App
